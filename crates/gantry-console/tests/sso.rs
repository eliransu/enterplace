//! Console single sign-on against a mock OpenID Connect provider on 127.0.0.1, with keys made in the test.
//! Each test runs its own provider on a port of 127.0.0.1 the system picks.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, header},
    routing::{get, post},
};
use gantry_console::{ConsoleConfig, router};
use gantry_core::{audit::AuditLog, id::sha256_hex};
use http_body_util::BodyExt;
use num_bigint::BigUint;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const HOST: &str = "127.0.0.1:20299";
const CLIENT_ID: &str = "gantry-console";
// Setting a variable needs `unsafe` in this edition, which the workspace forbids, so the secret is a
// variable cargo already sets for every test binary.
const SECRET_ENV: &str = "CARGO_PKG_NAME";
const ADMIN_KEY: &str = "gantry_admin_key_for_tests";

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn random(len: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// A 2048-bit RSA key, made here: ring signs with RSA but cannot make a key.
struct Rsa {
    n: BigUint,
    d: BigUint,
}

fn probably_prime(p: &BigUint) -> bool {
    let one = BigUint::from(1u32);
    let p1 = p - &one;
    let mut d = p1.clone();
    let mut r = 0;
    while !d.bit(0) {
        d >>= 1;
        r += 1;
    }
    // Twenty Miller-Rabin rounds with fixed prime bases: plenty for a test key, which needs no secrecy.
    [
        2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    ]
    .iter()
    .all(|a| {
        let mut x = BigUint::from(*a).modpow(&d, p);
        if x == one || x == p1 {
            return true;
        }
        for _ in 1..r {
            x = x.modpow(&BigUint::from(2u32), p);
            if x == p1 {
                return true;
            }
        }
        false
    })
}

fn prime(e: &BigUint) -> Result<BigUint, Error> {
    const SMALL: [u32; 30] = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127,
    ];
    loop {
        let mut bytes = random(128)?;
        bytes[0] |= 0xC0; // two top bits, so p * q has 2048 bits
        bytes[127] |= 1;
        let p = BigUint::from_bytes_be(&bytes);
        if SMALL.iter().any(|s| (&p % *s).bits() == 0) {
            continue;
        }
        let one = BigUint::from(1u32);
        if (&p - &one) % e != BigUint::from(0u32) && probably_prime(&p) {
            return Ok(p);
        }
    }
}

impl Rsa {
    fn new() -> Result<Self, Error> {
        let e = BigUint::from(65537u32);
        let (p, q) = (prime(&e)?, prime(&e)?);
        let one = BigUint::from(1u32);
        let phi = (&p - &one) * (&q - &one);
        let d = e.modinv(&phi).ok_or("no inverse")?;
        Ok(Self { n: p * q, d })
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 9.2).
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let prefix = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let mut em = vec![0x00, 0x01];
        em.resize(256 - prefix.len() - 32 - 1, 0xff);
        em.push(0x00);
        em.extend_from_slice(&prefix);
        em.extend_from_slice(&sha256(message));
        let s = BigUint::from_bytes_be(&em)
            .modpow(&self.d, &self.n)
            .to_bytes_be();
        let mut out = vec![0u8; 256 - s.len()];
        out.extend_from_slice(&s);
        out
    }

    fn jwk(&self, kid: &str) -> Value {
        json!({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
               "n": b64url(&self.n.to_bytes_be()), "e": b64url(&[1, 0, 1])})
    }
}

struct Ec(EcdsaKeyPair);

impl Ec {
    fn new() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| e.to_string())?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|e| e.to_string())?;
        Ok(Self(pair))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .0
            .sign(&SystemRandom::new(), message)
            .map_err(|e| e.to_string())?
            .as_ref()
            .to_vec())
    }

    fn jwk(&self, kid: &str) -> Value {
        let point = self.0.public_key().as_ref();
        json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig",
               "x": b64url(&point[1..33]), "y": b64url(&point[33..65])})
    }
}

enum Signer<'a> {
    Rsa(&'a Rsa),
    Ec(&'a Ec),
}

fn jwt(signer: &Signer<'_>, kid: &str, claims: &Value) -> Result<String, Error> {
    let alg = match signer {
        Signer::Rsa(_) => "RS256",
        Signer::Ec(_) => "ES256",
    };
    let input = format!(
        "{}.{}",
        b64url(
            json!({"alg": alg, "kid": kid, "typ": "JWT"})
                .to_string()
                .as_bytes()
        ),
        b64url(claims.to_string().as_bytes())
    );
    let sig = match signer {
        Signer::Rsa(k) => k.sign(input.as_bytes()),
        Signer::Ec(k) => k.sign(input.as_bytes())?,
    };
    Ok(format!("{input}.{}", b64url(&sig)))
}

/// What the mock provider serves: its keys, and the one code it will trade for a token.
#[derive(Default)]
struct Mock {
    issuer: String,
    /// Set to make the discovery document lie: another issuer, or another token endpoint.
    doc_issuer: Option<String>,
    token_endpoint: Option<String>,
    jwks: Vec<Value>,
    /// (code, ID token, PKCE challenge)
    grant: Option<(String, String, String)>,
}

type Shared = Arc<Mutex<Mock>>;

fn lock(m: &Shared) -> std::sync::MutexGuard<'_, Mock> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn discovery(State(m): State<Shared>) -> String {
    let m = lock(&m);
    let issuer = m.issuer.clone();
    json!({
        "issuer": m.doc_issuer.clone().unwrap_or(issuer.clone()),
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": m.token_endpoint.clone().unwrap_or(format!("{issuer}/token")),
        "jwks_uri": format!("{issuer}/jwks"),
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
    })
    .to_string()
}

async fn jwks(State(m): State<Shared>) -> String {
    json!({ "keys": lock(&m).jwks.clone() }).to_string()
}

async fn token(State(m): State<Shared>, headers: HeaderMap, body: String) -> (StatusCode, String) {
    let field = |name: &str| {
        body.split('&')
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .unwrap_or("")
            .to_string()
    };
    let basic = format!(
        "Basic {}",
        std_b64(format!("{CLIENT_ID}:{}", env!("CARGO_PKG_NAME")).as_bytes())
    );
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(basic.as_str());
    let grant = lock(&m).grant.take();
    match grant {
        Some((code, id_token, challenge))
            if authorized
                && field("grant_type") == "authorization_code"
                && field("code") == code
                && b64url(&sha256(field("code_verifier").as_bytes())) == challenge =>
        {
            (
                StatusCode::OK,
                json!({"access_token": "at", "token_type": "Bearer", "id_token": id_token})
                    .to_string(),
            )
        }
        _ => (
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_grant"}).to_string(),
        ),
    }
}

fn std_b64(bytes: &[u8]) -> String {
    let url = b64url(bytes).replace('-', "+").replace('_', "/");
    let pad = (4 - url.len() % 4) % 4;
    url + &"=".repeat(pad)
}

struct Setup {
    app: Router,
    dir: PathBuf,
    mock: Shared,
    issuer: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn setup() -> Result<Setup, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let issuer = format!("http://127.0.0.1:{port}");
    let mock: Shared = Arc::new(Mutex::new(Mock {
        issuer: issuer.clone(),
        ..Mock::default()
    }));
    let provider = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(mock.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, provider).await;
    });

    let dir = std::env::temp_dir().join(format!("gantry-sso-{}-{port}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = format!(
        "version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
console:
  sso:
    issuer: {issuer}
    client_id: {CLIENT_ID}
    client_secret_env: {SECRET_ENV}
    redirect_url: http://{HOST}/console/sso/callback
    allowed_domains: [example.com]
    allowed_emails: [guest@partner.org]
    role_claim: groups
    admin_values: [gantry-admins]
    read_only_values: [gantry-viewers]
    self_issue:
      allowed_domains: [example.com]
      team: developers
      expires_days: 30
"
    );
    std::fs::write(dir.join("gantry.policy.yaml"), policy)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n",
            sha256_hex(ADMIN_KEY.as_bytes())
        ),
    )?;
    let log = Arc::new(AuditLog::open(&dir.join("gantry-audit.jsonl"))?);
    let config = ConsoleConfig {
        policy: dir.join("gantry.policy.yaml"),
        keys: dir.join("gantry.keys.yaml"),
        audit: dir.join("gantry-audit.jsonl"),
        log: Some(log),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router(config)),
        dir,
        mock,
        issuer,
        server,
    })
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    form: &str,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))?;
    let response = app.clone().oneshot(request).await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

/// The value of a cookie the response sets.
fn set_cookie(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix(&format!("{name}=")))
        .and_then(|v| v.split(';').next())
        .unwrap_or("")
        .to_string()
}

fn param(url: &str, name: &str) -> String {
    url.split(['?', '&'])
        .find_map(|p| p.strip_prefix(&format!("{name}=")))
        .unwrap_or("")
        .to_string()
}

/// A started sign-in: the state cookie, and what the authorization request carried.
struct Started {
    cookie: String,
    state: String,
    nonce: String,
    challenge: String,
}

async fn start(s: &Setup) -> Result<Started, Error> {
    let (status, headers, body) = send(&s.app, "GET", "/console/sso/start", "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let to = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(to.starts_with(&format!("{}/authorize?", s.issuer)), "{to}");
    assert_eq!(param(to, "code_challenge_method"), "S256");
    assert_eq!(param(to, "client_id"), CLIENT_ID);
    assert!(to.contains("&scope=openid%20email%20profile&"), "{to}");
    let state = param(to, "state");
    let cookie = set_cookie(&headers, "gantry_sso");
    // The cookie carries the state, sealed: the server keeps nothing for a sign-in it started.
    assert!(cookie.starts_with(&format!("{state}.")), "{cookie}");
    Ok(Started {
        cookie,
        state,
        nonce: param(to, "nonce"),
        challenge: param(to, "code_challenge"),
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn claims(s: &Setup, nonce: &str) -> Value {
    json!({
        "iss": s.issuer, "aud": CLIENT_ID, "sub": "u1", "exp": now() + 300, "iat": now(),
        "nonce": nonce, "email": "dana@example.com", "email_verified": true, "groups": ["staff", "gantry-admins"],
    })
}

/// Comes back from the provider with `token` for the sign-in `started`.
async fn finish(
    s: &Setup,
    started: &Started,
    token: String,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    lock(&s.mock).grant = Some(("code-1".into(), token, started.challenge.clone()));
    send(
        &s.app,
        "GET",
        &format!("/console/sso/callback?code=code-1&state={}", started.state),
        &format!("gantry_sso={}", started.cookie),
        "",
    )
    .await
}

fn admin_records(s: &Setup) -> Result<Vec<Value>, Error> {
    Ok(std::fs::read_to_string(s.dir.join("gantry-audit.jsonl"))?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|r| r["event"] == "admin")
        .collect())
}

/// Asserts the last sign-in was refused with `code`, shown on the sign-in page and on the record.
fn assert_refused(
    s: &Setup,
    (status, headers, body): &(StatusCode, HeaderMap, String),
    code: &str,
    says: &str,
) -> TestResult {
    assert_eq!(*status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains(says), "{body}");
    // Shown in a banner above the sign-in choices: the key field was not used, so it is left at rest.
    assert!(
        body.contains(r#"<div class="g-banner" role="alert""#) && !body.contains("aria-invalid"),
        "{body}"
    );
    assert_eq!(set_cookie(headers, "gantry_console"), "");
    let records = admin_records(s)?;
    let last = records.last().ok_or("no admin record")?;
    assert_eq!(last["action"], "console_sign_in");
    assert_eq!(last["verdict"], "refused");
    assert_eq!(last["code"], code);
    assert_eq!(last["target"]["via"], "sso");
    Ok(())
}

#[tokio::test]
async fn an_rs256_admin_signs_in_is_recorded_and_signs_out() -> TestResult {
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let (status, _, page) = send(&s.app, "GET", "/console/sign-in", "", "").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"href="/console/sso/start""#));

    let started = start(&s).await?;
    let token = jwt(&Signer::Rsa(&rsa), "r1", &claims(&s, &started.nonce))?;
    let (status, headers, body) = finish(&s, &started, token).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(r#"http-equiv="refresh" content="0; url=/console/start""#));
    let session = set_cookie(&headers, "gantry_console");
    assert_eq!(session.len(), 64);
    let cookie = format!("gantry_console={session}");

    let (status, _, page) = send(&s.app, "GET", "/console/audit", &cookie, "").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(
            r#"g-muted">dana@example.com</span><span class="t-small g-muted">admin</span>"#
        ),
        "{page}"
    );

    // The state is used once: the same callback again is refused.
    let (status, _, _) = finish(&s, &started, "x".into()).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    send(&s.app, "GET", "/console/sign-out", &cookie, "").await?;
    let (status, _, _) = send(&s.app, "GET", "/console/audit", &cookie, "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let records = admin_records(&s)?;
    let signed_in = records
        .iter()
        .find(|r| r["action"] == "console_sign_in" && r["verdict"] == "allow")
        .ok_or("no sign-in record")?;
    assert_eq!(signed_in["person"], "dana@example.com");
    assert_eq!(signed_in["team"], Value::Null);
    assert_eq!(signed_in["target"], json!({"via": "sso", "role": "admin"}));
    let out = records.last().ok_or("no record")?;
    assert_eq!(out["action"], "console_sign_out");
    assert_eq!(out["person"], "dana@example.com");
    Ok(())
}

#[tokio::test]
async fn an_es256_viewer_signs_in_read_only_and_cannot_issue_a_key() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["email"] = json!("Guest@Partner.org");
    c["groups"] = json!("gantry-viewers");
    let (status, headers, body) = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cookie = format!("gantry_console={}", set_cookie(&headers, "gantry_console"));
    let (_, _, page) = send(&s.app, "GET", "/console/people", &cookie, "").await?;
    // The name on one line and the role on the next.
    assert!(
        page.contains(r#"<span class="t-mono-sm g-muted">guest@partner.org</span><span class="t-small g-muted">read only</span>"#),
        "{page}"
    );
    // A read-only person never sees an action they cannot take, and is told why.
    assert!(
        !page.contains("/console/people?issue=1")
            && !page.contains("Revoke key")
            && page.contains("You are signed in read only"),
        "{page}"
    );
    let (_, _, page) = send(&s.app, "GET", "/console/people?issue=1", &cookie, "").await?;
    assert!(!page.contains(r#"role="dialog""#), "{page}");

    let keys_before = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    let (status, _, page) = send(
        &s.app,
        "POST",
        "/console/people/issue",
        &cookie,
        "name=x.y&team=t",
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("signed in read only"), "{page}");
    assert_eq!(
        std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?,
        keys_before
    );
    let last = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(last["action"], "issue_key");
    assert_eq!(last["code"], "read_only");
    assert_eq!(last["person"], "guest@partner.org");
    Ok(())
}

#[tokio::test]
async fn a_wrong_nonce_is_refused() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let token = jwt(&Signer::Ec(&ec), "e1", &claims(&s, "another-nonce"))?;
    let got = finish(&s, &started, token).await?;
    assert_refused(&s, &got, "sso_nonce", "nonce does not match")
}

#[tokio::test]
async fn a_wrong_audience_is_refused() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["aud"] = json!("some-other-app");
    let got = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
    assert_refused(&s, &got, "sso_audience", "issued for another app")
}

#[tokio::test]
async fn an_expired_token_is_refused() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["exp"] = json!(now() - 3600);
    let got = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
    assert_refused(&s, &got, "sso_expired", "has expired")
}

#[tokio::test]
async fn a_bad_signature_is_refused() -> TestResult {
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let started = start(&s).await?;
    let token = jwt(&Signer::Rsa(&rsa), "r1", &claims(&s, &started.nonce))?;
    // The claims swapped after signing: someone else's email under a valid signature of the original.
    let mut forged = claims(&s, &started.nonce);
    forged["email"] = json!("mallory@example.com");
    let parts: Vec<&str> = token.split('.').collect();
    let token = format!(
        "{}.{}.{}",
        parts[0],
        b64url(forged.to_string().as_bytes()),
        parts[2]
    );
    let got = finish(&s, &started, token).await?;
    assert_refused(&s, &got, "sso_signature", "signature does not match")
}

#[tokio::test]
async fn a_key_id_not_in_the_key_set_is_refused_after_fetching_it_again() -> TestResult {
    let s = setup().await?;
    let (ec, other) = (Ec::new()?, Ec::new()?);
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let token = jwt(&Signer::Ec(&other), "e9", &claims(&s, &started.nonce))?;
    let got = finish(&s, &started, token).await?;
    assert_refused(&s, &got, "sso_unknown_key", "key &quot;e9&quot;")?;

    // A key the provider added since the keys were cached is found by fetching them again.
    lock(&s.mock).jwks = vec![ec.jwk("e1"), other.jwk("e9")];
    let started = start(&s).await?;
    let token = jwt(&Signer::Ec(&other), "e9", &claims(&s, &started.nonce))?;
    let (status, _, body) = finish(&s, &started, token).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test]
async fn an_email_outside_the_allowed_domains_or_with_no_role_is_refused() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["email"] = json!("eve@elsewhere.com");
    let got = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
    assert_refused(&s, &got, "sso_email", "eve@elsewhere.com may not sign in")?;
    let last = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(last["person"], "eve@elsewhere.com");

    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["groups"] = json!(["staff"]);
    let got = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
    assert_refused(&s, &got, "sso_role", "has no console role")
}

#[tokio::test]
async fn a_state_this_browser_did_not_start_is_refused() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let mine = start(&s).await?;
    let theirs = start(&s).await?;
    let token = jwt(&Signer::Ec(&ec), "e1", &claims(&s, &theirs.nonce))?;
    lock(&s.mock).grant = Some(("code-1".into(), token, theirs.challenge.clone()));
    // The callback carries the other sign-in's state, with this browser's cookie.
    let got = send(
        &s.app,
        "GET",
        &format!("/console/sso/callback?code=code-1&state={}", theirs.state),
        &format!("gantry_sso={}", mine.cookie),
        "",
    )
    .await?;
    assert_refused(&s, &got, "sso_state", "did not start")
}

#[tokio::test]
async fn a_flood_of_sign_in_starts_locks_nobody_out_and_is_recorded_once_a_minute() -> TestResult {
    // QA10-4. A sign-in started before the flood, one started after it, and the flood itself.
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let before = start(&s).await?;
    for _ in 0..1500 {
        let (status, _, body) = send(&s.app, "GET", "/console/sso/start", "", "").await?;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    }
    let after = start(&s).await?;
    for started in [&before, &after] {
        let token = jwt(&Signer::Ec(&ec), "e1", &claims(&s, &started.nonce))?;
        let (status, _, body) = finish(&s, started, token).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    // Each state is used once, sealed cookie or not.
    let again = finish(&s, &after, "x".into()).await?;
    assert_refused(&s, &again, "sso_state", "already used")?;
    let records = admin_records(&s)?;
    let floods: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "console_sso_starts")
        .collect();
    assert_eq!(floods.len(), 1, "{floods:?}");
    assert_eq!(floods[0]["target"]["starts"], 100);
    Ok(())
}

#[tokio::test]
async fn a_forged_or_expired_state_cookie_is_refused() -> TestResult {
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let token = jwt(&Signer::Ec(&ec), "e1", &claims(&s, &started.nonce))?;
    let (state, rest) = started.cookie.split_once('.').ok_or("no seal")?;
    let (expires, seal) = rest.split_once('.').ok_or("no seal")?;
    let later: u64 = expires.parse::<u64>()? + 3600;
    for (cookie, says) in [
        // A state of the attacker's choosing, the old seal: the seal no longer matches.
        (
            format!("{}.{expires}.{seal}", "0".repeat(state.len())),
            "did not start",
        ),
        // A later expiry under the old seal.
        (format!("{state}.{later}.{seal}"), "did not start"),
        // The bare state, as the cookie used to be.
        (state.to_string(), "did not start"),
    ] {
        lock(&s.mock).grant = Some(("code-1".into(), token.clone(), started.challenge.clone()));
        let path = format!(
            "/console/sso/callback?code=code-1&state={}",
            cookie.split('.').next().unwrap_or("")
        );
        let got = send(&s.app, "GET", &path, &format!("gantry_sso={cookie}"), "").await?;
        assert_refused(&s, &got, "sso_state", says)?;
    }
    Ok(())
}

#[tokio::test]
async fn unverified_look_alike_and_misissued_identities_are_refused() -> TestResult {
    // QA10-5 S5, S6, S9.
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    for (change, code, says) in [
        (
            json!({"email_verified": false}),
            "sso_email",
            "not verified",
        ),
        (
            json!({"email": "eve@evilexample.com"}),
            "sso_email",
            "eve@evilexample.com may not sign in",
        ),
        (
            json!({"email": "eve@sub.example.com"}),
            "sso_email",
            "eve@sub.example.com may not sign in",
        ),
        (
            json!({"iss": "https://elsewhere.example.com"}),
            "sso_issuer",
            "was issued by",
        ),
    ] {
        let started = start(&s).await?;
        let mut c = claims(&s, &started.nonce);
        for (key, value) in change.as_object().ok_or("not an object")? {
            c[key] = value.clone();
        }
        let got = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
        assert_refused(&s, &got, code, says)?;
    }
    Ok(())
}

#[tokio::test]
async fn a_discovery_document_for_another_issuer_or_with_a_plain_http_endpoint_is_refused()
-> TestResult {
    // QA10-5 S7 and S8: the client secret must never go to a token endpoint over plain http.
    for (doc_issuer, token_endpoint, code, says) in [
        (
            Some("https://elsewhere.example.com"),
            None,
            "sso_issuer",
            "names issuer",
        ),
        (
            None,
            Some("http://idp.example.com/token"),
            "sso_provider",
            "not an https URL",
        ),
    ] {
        let s = setup().await?;
        {
            let mut m = lock(&s.mock);
            m.doc_issuer = doc_issuer.map(str::to_string);
            m.token_endpoint = token_endpoint.map(str::to_string);
        }
        let got = send(&s.app, "GET", "/console/sso/start", "", "").await?;
        assert_refused(&s, &got, code, says)?;
    }
    Ok(())
}

#[tokio::test]
async fn a_read_only_person_cannot_revoke_and_a_person_removed_from_the_policy_is_signed_out()
-> TestResult {
    // QA10-5 C3 and C5.
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["email"] = json!("guest@partner.org");
    c["groups"] = json!(["gantry-viewers"]);
    let (status, headers, body) = finish(&s, &started, jwt(&Signer::Ec(&ec), "e1", &c)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cookie = format!("gantry_console={}", set_cookie(&headers, "gantry_console"));
    let keys = s.dir.join("gantry.keys.yaml");
    let before = std::fs::read_to_string(&keys)?;
    let sha = sha256_hex(ADMIN_KEY.as_bytes());
    let (status, _, page) = send(
        &s.app,
        "POST",
        "/console/people/revoke",
        &cookie,
        &format!("sha256={sha}&confirm=noa.bar"),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
    assert_eq!(std::fs::read_to_string(&keys)?, before);
    let last = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(
        (last["action"].as_str(), last["code"].as_str()),
        (Some("revoke_key"), Some("read_only"))
    );

    // The email leaves the policy: the next page is the sign-in page, with no restart.
    let (status, _, _) = send(&s.app, "GET", "/console/audit", &cookie, "").await?;
    assert_eq!(status, StatusCode::OK);
    let policy = s.dir.join("gantry.policy.yaml");
    let text = std::fs::read_to_string(&policy)?;
    std::fs::write(
        &policy,
        text.replace(
            "allowed_emails: [guest@partner.org]",
            "allowed_emails: [other@partner.org]",
        ),
    )?;
    let (status, headers, _) = send(&s.app, "GET", "/console/audit", &cookie, "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/console/sign-in")
    );
    Ok(())
}

#[test]
fn a_policy_with_an_unsafe_or_incomplete_sso_section_is_refused_with_the_fix() -> TestResult {
    let policy = "version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
console:
  sso:
    issuer: http://login.example.com
    client_id: gantry-console
    client_secret_env: the secret itself
    redirect_url: https://gantry.example.com/elsewhere
    role_claim: groups
";
    let path = std::path::Path::new("gantry.policy.yaml");
    let errors = gantry_core::config::load_texts(path, policy, path, "")
        .err()
        .ok_or("the policy was accepted")?
        .join("\n");
    for says in [
        "gantry.policy.yaml:14: the sso issuer must be an https URL",
        "gantry.policy.yaml:16: client_secret_env is the name of an environment variable",
        "gantry.policy.yaml:17: redirect_url must be the console's callback",
        "sso lets nobody in",
        "sso gives nobody a role",
    ] {
        assert!(errors.contains(says), "{errors}");
    }
    Ok(())
}

#[tokio::test]
async fn a_flood_of_refused_callbacks_neither_empties_the_replay_list_nor_fills_the_log()
-> TestResult {
    // QA11-7. One real sign-in, then more refused start-and-callback pairs than the replay list holds. Its state
    // must still be refused as used, and the refusals are recorded one by one only up to a minute's limit.
    let s = setup().await?;
    let ec = Ec::new()?;
    lock(&s.mock).jwks = vec![ec.jwk("e1")];
    let real = start(&s).await?;
    let token = jwt(&Signer::Ec(&ec), "e1", &claims(&s, &real.nonce))?;
    let (status, _, body) = finish(&s, &real, token.clone()).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let flooding = std::time::Instant::now();
    for _ in 0..10_050 {
        let (_, headers, _) = send(&s.app, "GET", "/console/sso/start", "", "").await?;
        let to = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let (state, cookie) = (param(to, "state"), set_cookie(&headers, "gantry_sso"));
        let (status, _, _) = send(
            &s.app,
            "GET",
            &format!("/console/sso/callback?error=x&state={state}"),
            &format!("gantry_sso={cookie}"),
            "",
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, body) = finish(&s, &real, token).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("already used"), "{body}");
    let records = admin_records(&s)?;
    let refused = records
        .iter()
        .filter(|r| r["action"] == "console_sign_in" && r["verdict"] == "refused")
        .count();
    let summaries: Vec<&Value> = records
        .iter()
        .filter(|r| r["action"] == "console_sso_refusals")
        .collect();
    // The limit is 100 a minute of the machine's clock. A debug build on a slow CI runner can take more than a minute
    // over the flood: each minute that closed may add its own 100 and its one summary, never more.
    let minutes = usize::try_from(flooding.elapsed().as_secs() / 60).unwrap_or(usize::MAX);
    assert!(
        refused <= 100 * (minutes + 1),
        "{refused} refusals recorded one by one in {minutes} whole minutes"
    );
    assert!(
        summaries.len() <= minutes,
        "summed up before its minute closed"
    );
    // QA12-3. The cap is per client address: another address is still recorded one by one during the flood.
    let mut request = Request::builder()
        .uri("/console/sso/callback?error=x&state=y")
        .header(header::HOST, HOST)
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [192, 0, 2, 7],
            4000,
        ))));
    let response = s.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let records = admin_records(&s)?;
    let other = records.last().ok_or("no record")?;
    assert_eq!(
        (&other["action"], &other["client"]),
        (&json!("console_sign_in"), &json!("192.0.2.7")),
        "{other}"
    );
    // When the flooded minute closes, one summary carries its true count: the 10,050 refusals and the replay.
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    let mut summaries = Vec::new();
    for _ in 0..200 {
        summaries = admin_records(&s)?
            .into_iter()
            .filter(|r| r["action"] == "console_sso_refusals")
            .collect();
        if !summaries.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        tokio::task::yield_now().await;
    }
    if minutes > 0 {
        // The flood spanned minutes, so its count is split between their summaries.
        assert!(!summaries.is_empty(), "no summary of the flood");
        return Ok(());
    }
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0]["target"]["refusals"], 10_051, "{summaries:?}");
    assert_eq!(summaries[0]["target"]["client"], "unknown");
    Ok(())
}

/// Plays the browser of a `gantry login`: opens the address the CLI gave, signs in at the mock provider as `email`,
/// and follows the console back to the CLI's listener on 127.0.0.1. Returns where the console sent the browser and
/// what the CLI's listener answered.
async fn browse(
    s: &Setup,
    rsa: &Rsa,
    opened: &str,
    email: &str,
) -> Result<(String, String), Error> {
    browse_in(s, rsa, opened, email, json!([])).await
}

/// `browse`, with the groups the identity provider says the person is in.
async fn browse_in(
    s: &Setup,
    rsa: &Rsa,
    opened: &str,
    email: &str,
    groups: Value,
) -> Result<(String, String), Error> {
    let path = &opened[opened.find("/console/").ok_or("not a console address")?..];
    let (status, headers, body) = send(&s.app, "GET", path, "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let to = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let (sso, cli) = (
        set_cookie(&headers, "gantry_sso"),
        set_cookie(&headers, "gantry_cli"),
    );
    assert!(!cli.is_empty(), "no CLI cookie");
    let mut claims = claims(s, &param(&to, "nonce"));
    claims["email"] = email.into();
    // No console role: a personal key needs none.
    claims["groups"] = groups;
    let token = jwt(&Signer::Rsa(rsa), "r1", &claims)?;
    lock(&s.mock).grant = Some(("code-1".into(), token, param(&to, "code_challenge")));
    let (status, headers, body) = send(
        &s.app,
        "GET",
        &format!(
            "/console/sso/callback?code=code-1&state={}",
            param(&to, "state")
        ),
        &format!("gantry_sso={sso}; gantry_cli={cli}"),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let back = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(
        set_cookie(&headers, "gantry_console"),
        "",
        "a CLI sign-in opened a console session"
    );
    let rest = back
        .strip_prefix("http://127.0.0.1:")
        .ok_or(format!("not sent back to the CLI: {back}"))?;
    let (port, target) = rest.split_at(rest.find('/').ok_or("no path")?);
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port.parse::<u16>()?)).await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .await?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await?;
    Ok((back, answer))
}

/// M12-1. The CLI's listener sends the browser on to a console page in the brand's styles, never a bare text page.
async fn handoff(s: &Setup, answer: &str, ok: bool) -> TestResult {
    let to = format!("/console/cli/done?ok={}", u8::from(ok));
    assert!(
        answer.starts_with("HTTP/1.1 303") && answer.contains(&format!("{to}\r\n")),
        "{answer}"
    );
    let (status, _, page) = send(&s.app, "GET", &to, "", "").await?;
    assert_eq!(status, StatusCode::OK);
    for part in [
        "/console/assets/bundle.css",
        "/console/assets/console.js",
        r#"<span class="g-mark""#,
        "gantry login",
    ] {
        assert!(page.contains(part), "missing {part}: {page}");
    }
    let (title, banner) = if ok {
        ("Signed in", false)
    } else {
        ("Not signed in", true)
    };
    assert!(page.contains(&format!(">{title}</h1>")), "{page}");
    assert_eq!(page.contains("g-banner"), banner, "{page}");
    assert!(!page.contains("admin key"), "{page}");
    Ok(())
}

/// Serves the console on a port of 127.0.0.1, so the CLI side can call it over HTTP.
async fn serve(s: &Setup) -> Result<(String, tokio::task::JoinHandle<()>), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let app = s.app.clone();
    Ok((
        url,
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn gantry_login_issues_a_personal_key_bound_to_the_email_with_an_expiry_and_a_record()
-> TestResult {
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let (url, server) = serve(&s).await?;
    let (tell, opened) = tokio::sync::oneshot::channel();
    let login = gantry_console::cli::login(&url, move |address| {
        let _ = tell.send(address.to_string());
    });
    let browser = async {
        let opened = opened.await?;
        browse(&s, &rsa, &opened, "dana@example.com").await
    };
    let (got, back) = tokio::join!(login, browser);
    server.abort();
    let got = got?;
    let (back, answer) = back?;
    handoff(&s, &answer, true).await?;
    // The browser only ever saw a one-use code, never the key.
    assert!(!back.contains(&got.key) && back.contains("code="), "{back}");
    assert!(got.key.starts_with("gantry_"));
    assert_eq!(
        (got.name.as_str(), got.team.as_str()),
        ("dana@example.com", "developers")
    );
    let in_30_days = gantry_core::audit::rfc3339(
        SystemTime::now() + std::time::Duration::from_secs(30 * 86_400),
    );
    assert_eq!(got.expires[..10], in_30_days[..10], "{}", got.expires);
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    let hash = sha256_hex(got.key.as_bytes());
    assert!(
        keys.contains(&format!("  - name: dana@example.com\n    team: developers\n    sha256: {hash}\n    expires: {}\n", got.expires)),
        "{keys}"
    );
    let records = admin_records(&s)?;
    let issued = records.last().ok_or("no record")?;
    assert_eq!(issued["action"], "self_issue_key");
    assert_eq!(issued["person"], "dana@example.com");
    assert_eq!(issued["target"]["sha256_prefix"], &hash[..8]);
    assert_eq!(issued["target"]["expires"], got.expires.as_str());
    // The code was used: trading it again gets nothing.
    let code = param(&back, "code");
    let (status, _, body) = send(
        &s.app,
        "POST",
        "/console/cli/token",
        "",
        &format!("code={code}&verifier=x"),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("invalid_grant"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gantry_login_holds_a_personal_key_to_the_policy_s_key_bounds() -> TestResult {
    let s = setup().await?;
    // self_issue asks for 30 days; the bounds allow 7, and give the key a budget.
    with_policy(
        &s,
        "key_bounds:\n  max_days: 7\n  max_budget: { usd: 5, per: month }\n",
        true,
    )?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let (url, server) = serve(&s).await?;
    let (tell, opened) = tokio::sync::oneshot::channel();
    let login = gantry_console::cli::login(&url, move |address| {
        let _ = tell.send(address.to_string());
    });
    let browser = async {
        let opened = opened.await?;
        browse(&s, &rsa, &opened, "dana@example.com").await
    };
    let (got, back) = tokio::join!(login, browser);
    server.abort();
    let got = got?;
    let (_, answer) = back?;
    handoff(&s, &answer, true).await?;
    let in_7_days =
        gantry_core::audit::rfc3339(SystemTime::now() + std::time::Duration::from_secs(7 * 86_400));
    assert_eq!(got.expires[..10], in_7_days[..10], "{}", got.expires);
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    let hash = sha256_hex(got.key.as_bytes());
    let entry = keys
        .split("  - name: ")
        .find(|e| e.contains(&hash))
        .ok_or("the key is not in the keys file")?;
    assert!(
        entry.contains("usd: 5") && entry.contains("per: month"),
        "{keys}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gantry_login_refuses_an_email_policy_does_not_let_self_issue_and_a_wrong_verifier()
-> TestResult {
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let (url, server) = serve(&s).await?;
    // guest@partner.org may sign in to the console, but self_issue lets only example.com get keys.
    let (tell, opened) = tokio::sync::oneshot::channel();
    let login = gantry_console::cli::login(&url, move |address| {
        let _ = tell.send(address.to_string());
    });
    let browser = async {
        let opened = opened.await?;
        browse(&s, &rsa, &opened, "guest@partner.org").await
    };
    let (got, back) = tokio::join!(login, browser);
    let err = got.err().ok_or("a key was issued")?;
    assert!(err.contains("may not get a key"), "{err}");
    let (back, answer) = back?;
    assert!(back.contains("error=sso_self_issue"));
    handoff(&s, &answer, false).await?;
    let last = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(last["code"], "sso_self_issue");
    assert_eq!(last["verdict"], "refused");

    // A code taken by someone who does not hold the verifier is refused, and spent.
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let start = format!(
        "/console/cli/login?cli_port=1&cli_state=abcdefghijklmnop&cli_challenge={challenge}"
    );
    let (status, headers, _) = send(&s.app, "GET", &start, "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let to = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut claims = claims(&s, &param(&to, "nonce"));
    claims["groups"] = json!([]);
    lock(&s.mock).grant = Some((
        "code-1".into(),
        jwt(&Signer::Rsa(&rsa), "r1", &claims)?,
        param(&to, "code_challenge"),
    ));
    let (_, headers, _) = send(
        &s.app,
        "GET",
        &format!(
            "/console/sso/callback?code=code-1&state={}",
            param(&to, "state")
        ),
        &format!(
            "gantry_sso={}; gantry_cli={}",
            set_cookie(&headers, "gantry_sso"),
            set_cookie(&headers, "gantry_cli")
        ),
        "",
    )
    .await?;
    let back = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let code = param(&back, "code");
    assert_eq!(code.len(), 64, "{back}");
    for verifier in ["wrong", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"] {
        let (status, _, body) = send(
            &s.app,
            "POST",
            "/console/cli/token",
            "",
            &format!("code={code}&verifier={verifier}"),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    // A link that was changed is refused before the provider is asked.
    let (status, _, body) = send(
        &s.app,
        "GET",
        "/console/cli/login?cli_port=1&cli_state=short&cli_challenge=x",
        "",
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // m12-10. Not the console sign-in with its admin key field: a developer ran gantry login.
    assert!(
        body.contains("This gantry login link does not work")
            && body.contains("incomplete or was changed")
            && body.contains(r#"<span class="g-command__text t-mono">gantry login</span>"#)
            && !body.contains("Admins only")
            && !body.contains(r#"name="key""#),
        "{body}"
    );
    // A console sign-in after an abandoned gantry login clears its cookie.
    let (_, headers, _) = send(&s.app, "GET", "/console/sso/start", "", "").await?;
    assert!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().is_ok_and(|v| v.starts_with("gantry_cli=;")))
    );
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gantry_login_refuses_an_email_a_key_name_cannot_hold_before_recording_an_issue()
-> TestResult {
    // QA14-13: dana+ci@example.com passed self_issue, was recorded as issued, then failed to be written.
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let (url, server) = serve(&s).await?;
    let (tell, opened) = tokio::sync::oneshot::channel();
    let login = gantry_console::cli::login(&url, move |address| {
        let _ = tell.send(address.to_string());
    });
    let browser = async {
        let opened = opened.await?;
        browse(&s, &rsa, &opened, "dana+ci@example.com").await
    };
    let (got, _) = tokio::join!(login, browser);
    server.abort();
    let err = got.err().ok_or("a key was issued")?;
    assert!(
        err.contains("unusable_email") && err.contains("gantry key new"),
        "{err}"
    );
    assert!(
        !admin_records(&s)?
            .iter()
            .any(|r| r["action"] == "self_issue_key"),
        "no issue is recorded for a key that was never made"
    );
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    assert!(!keys.contains("dana"), "{keys}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_or_forged_gantry_login_cookie_never_ends_in_a_code() -> TestResult {
    // QA14-16 (LG2): the gantry_cli cookie is sealed; one whose port was changed, or whose seal is not the
    // console's, is not taken as a gantry login, so no code goes to any port.
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let start = format!(
        "/console/cli/login?cli_port=1&cli_state=abcdefghijklmnop&cli_challenge={challenge}"
    );
    let change_port = |c: &str| c.replacen("1.", "2.", 1);
    let bad_seal = |c: &str| match c.rsplit_once('.') {
        Some((sealed, _)) => format!("{sealed}.AAAA"),
        None => c.to_string(),
    };
    for tamper in [&change_port as &dyn Fn(&str) -> String, &bad_seal] {
        let (status, headers, _) = send(&s.app, "GET", &start, "", "").await?;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let to = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut claims = claims(&s, &param(&to, "nonce"));
        claims["groups"] = json!([]);
        lock(&s.mock).grant = Some((
            "code-1".into(),
            jwt(&Signer::Rsa(&rsa), "r1", &claims)?,
            param(&to, "code_challenge"),
        ));
        let cli = set_cookie(&headers, "gantry_cli");
        assert!(cli.starts_with("1."), "{cli}");
        let (_, back, _) = send(
            &s.app,
            "GET",
            &format!(
                "/console/sso/callback?code=code-1&state={}",
                param(&to, "state")
            ),
            &format!(
                "gantry_sso={}; gantry_cli={}",
                set_cookie(&headers, "gantry_sso"),
                tamper(&cli)
            ),
            "",
        )
        .await?;
        let location = back
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            !location.contains("127.0.0.1") && !location.contains("code="),
            "{location}"
        );
    }
    Ok(())
}

/// Adds `teams:` (and anything else) to the test policy, before its console section.
fn with_policy(s: &Setup, before_console: &str, self_issue_team: bool) -> TestResult {
    let path = s.dir.join("gantry.policy.yaml");
    let mut text = std::fs::read_to_string(&path)?
        .replace("console:\n", &format!("{before_console}console:\n"));
    if !self_issue_team {
        text = text.replace("      team: developers\n", "");
    }
    std::fs::write(&path, text)?;
    Ok(())
}

const TEAMS: &str = "teams:
  - name: payments
    owner: maya@example.com
    members: [maya@example.com]
    sso_values: [payments-eng]
  - name: web
    sso_values: [web-eng]
";

/// Runs `gantry login` for `email` in `groups`: the key's team, or the refusal.
async fn login_team(s: &Setup, rsa: &Rsa, email: &str, groups: Value) -> Result<String, Error> {
    let (url, server) = serve(s).await?;
    let (tell, opened) = tokio::sync::oneshot::channel();
    let login = gantry_console::cli::login(&url, move |address| {
        let _ = tell.send(address.to_string());
    });
    let browser = async {
        let opened = opened.await?;
        browse_in(s, rsa, &opened, email, groups).await
    };
    let (got, _) = tokio::join!(login, browser);
    server.abort();
    Ok(match got {
        Ok(got) => got.team,
        Err(err) => format!("refused: {err}"),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn gantry_login_puts_the_key_in_the_team_the_email_or_the_groups_name() -> TestResult {
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    with_policy(&s, TEAMS, false)?;
    // Listed by email; the email comes first even when a group names another team.
    assert_eq!(
        login_team(&s, &rsa, "maya@example.com", json!(["web-eng"])).await?,
        "payments"
    );
    // Placed by a group of the identity provider.
    assert_eq!(
        login_team(&s, &rsa, "dana@example.com", json!(["staff", "web-eng"])).await?,
        "web"
    );
    // In no team, and self_issue names no team to fall back on: refused, with the fix.
    let refused = login_team(&s, &rsa, "eve@example.com", json!(["staff"])).await?;
    assert!(
        refused.starts_with("refused") && refused.contains("is in no team"),
        "{refused}"
    );
    let last = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(last["code"], "sso_team");
    // With self_issue.team written, it is where such a person's key goes.
    let path = s.dir.join("gantry.policy.yaml");
    let text = std::fs::read_to_string(&path)?;
    std::fs::write(
        &path,
        text.replace(
            "      expires_days: 30",
            "      team: developers\n      expires_days: 30",
        ),
    )?;
    assert_eq!(
        login_team(&s, &rsa, "eve@example.com", json!(["staff"])).await?,
        "developers"
    );
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    for (name, team) in [
        ("maya@example.com", "payments"),
        ("dana@example.com", "web"),
        ("eve@example.com", "developers"),
    ] {
        assert!(
            keys.contains(&format!("  - name: {name}\n    team: {team}\n")),
            "{keys}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_role_kept_to_a_team_signs_in_by_group_and_sees_only_that_team() -> TestResult {
    let s = setup().await?;
    let rsa = Rsa::new()?;
    lock(&s.mock).jwks = vec![rsa.jwk("r1")];
    with_policy(
        &s,
        &format!(
            "{TEAMS}roles:
  - name: payments-lead
    permissions: [see_keys, issue_keys, see_records, see_spend]
    teams: [payments]
    sso_values: [payments-leads]
"
        ),
        true,
    )?;
    let keys = s.dir.join("gantry.keys.yaml");
    gantry_core::keyfile::add_entry(
        "maya.ci",
        "payments",
        "gantry_maya_ci_key_0123456789",
        false,
        &keys,
    )?;
    gantry_core::keyfile::add_entry(
        "omer.ci",
        "web",
        "gantry_omer_ci_key_0123456789",
        false,
        &keys,
    )?;
    // The admin key signs in first: a record of team platform, which the lead must not see.
    let (status, _, _) = send(
        &s.app,
        "POST",
        "/console/sign-in",
        "",
        &format!("key={ADMIN_KEY}"),
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let started = start(&s).await?;
    let mut c = claims(&s, &started.nonce);
    c["groups"] = json!(["payments-leads", "payments-eng"]);
    let (status, headers, body) = finish(&s, &started, jwt(&Signer::Rsa(&rsa), "r1", &c)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cookie = format!("gantry_console={}", set_cookie(&headers, "gantry_console"));
    let signed_in = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(signed_in["team"], "payments");
    assert_eq!(signed_in["target"]["role"], "payments-lead");

    let (_, _, page) = send(&s.app, "GET", "/console/people", &cookie, "").await?;
    assert!(
        page.contains("maya.ci") && !page.contains("omer.ci"),
        "{page}"
    );
    let (_, _, page) = send(&s.app, "GET", "/console/audit", &cookie, "").await?;
    assert!(page.contains("dana@example.com"), "{page}");
    assert!(!page.contains("noa.bar"), "{page}");
    // A key for another team is refused before it is made.
    let before = std::fs::read_to_string(&keys)?;
    let (status, _, page) = send(
        &s.app,
        "POST",
        "/console/people/issue",
        &cookie,
        "name=x.y&team=web",
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("keeps you to team payments"), "{page}");
    assert_eq!(std::fs::read_to_string(&keys)?, before);
    let (status, _, page) = send(
        &s.app,
        "POST",
        "/console/people/issue",
        &cookie,
        "name=x.y&team=payments",
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    Ok(())
}

#[tokio::test]
async fn the_scopes_setting_is_what_the_provider_is_asked_for_and_must_hold_openid() -> TestResult {
    let s = setup().await?;
    let path = s.dir.join("gantry.policy.yaml");
    let text = std::fs::read_to_string(&path)?;
    std::fs::write(
        &path,
        text.replace(
            "    role_claim: groups\n",
            "    role_claim: groups\n    scopes: openid email profile groups\n",
        ),
    )?;
    let (status, headers, body) = send(&s.app, "GET", "/console/sso/start", "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let to = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        to.contains("&scope=openid%20email%20profile%20groups&"),
        "{to}"
    );
    std::fs::write(
        &path,
        text.replace(
            "    role_claim: groups\n",
            "    role_claim: groups\n    scopes: email \"groups\"\n",
        ),
    )?;
    let errors = gantry_core::config::load(&path, None)
        .err()
        .ok_or("loaded")?
        .join("\n");
    assert!(
        errors.contains("scopes must be space separated scope names that include openid"),
        "{errors}"
    );
    Ok(())
}
