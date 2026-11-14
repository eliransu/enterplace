//! Console sign-in through a SAML 2.0 identity provider, end to end through the console's routes: the request
//! Gantry sends, the response a test identity provider signs with its key, and every refusal recorded.
//!
//! The response is written in canonical form, so its digest is the SHA-256 of its own text. That the
//! canonicalization agrees with another implementation is checked in the console's unit tests, against a response
//! signed with libxml2.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use gantry_console::{ConsoleConfig, router};
use gantry_core::{audit::AuditLog, id::sha256_hex, x509};
use http_body_util::BodyExt;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const HOST: &str = "127.0.0.1:20298";
const IDP: &str = "http://idp.example.com/metadata";
const SP: &str = "http://127.0.0.1:20298/console/saml/metadata";
const ACS: &str = "http://127.0.0.1:20298/console/saml/acs";
const CERT: &str = include_str!("fixtures/saml-idp.pem");
const KEY: &str = include_str!("fixtures/saml-idp-key.pem");
const ADMIN_KEY: &str = "gantry_admin_key_for_saml_tests";

struct Setup {
    app: Router,
    dir: PathBuf,
}

fn setup(name: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-saml-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let cert: String = CERT.lines().map(|l| format!("      {l}\n")).collect();
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
teams:
  - name: payments
    sso_values: [payments-eng]
console:
  saml:
    idp_entity_id: {IDP}
    idp_sso_url: https://idp.example.com/sso
    idp_certificate: |
{cert}    sp_entity_id: {SP}
    acs_url: {ACS}
    role_attribute: groups
    admin_values: [gantry-admins]
    read_only_values: [gantry-viewers]
    allowed_domains: [example.com]
    self_issue:
      allowed_domains: [example.com]
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
        // The identity provider's page posts the form: another site.
        .header(header::ORIGIN, "https://idp.example.com")
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
    let query = url.split_once('?').map_or("", |(_, q)| q);
    gantry_console::Form::parse(query).get(name).to_string()
}

fn enc(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Inflates DEFLATE stored blocks, as Gantry writes its request.
fn inflate_stored(mut data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let (&head, rest) = data.split_first().ok_or("empty")?;
        if head & 0b110 != 0 {
            return Err("not a stored block".into());
        }
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
        out.extend_from_slice(&rest[4..4 + len]);
        data = &rest[4 + len..];
        if head & 1 == 1 {
            return Ok(out);
        }
    }
}

/// A started sign-in: the request's ID and the cookie that holds it.
async fn start(s: &Setup) -> Result<(String, String), Error> {
    let (status, headers, body) = send(&s.app, "GET", "/console/saml/start", "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let to = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        to.starts_with("https://idp.example.com/sso?SAMLRequest="),
        "{to}"
    );
    let request = String::from_utf8(inflate_stored(
        &x509::base64_decode(&param(&to, "SAMLRequest")).ok_or("not base64")?,
    )?)?;
    let id = param(&to, "RelayState");
    assert!(request.contains(&format!("ID=\"{id}\"")), "{request}");
    assert!(request.contains(&format!("AssertionConsumerServiceURL=\"{ACS}\"")));
    assert!(request.contains(&format!("<saml:Issuer>{SP}</saml:Issuer>")));
    let cookie = set_cookie(&headers, "gantry_saml");
    assert!(cookie.starts_with(&format!("{id}.")), "{cookie}");
    Ok((id, cookie))
}

fn instant(unix: u64) -> String {
    let t = jiff::Timestamp::from_second(i64::try_from(unix).unwrap_or(0)).unwrap_or_default();
    t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the test identity provider puts in its answer.
struct Answer<'a> {
    request: String,
    email: &'a str,
    groups: &'a [&'a str],
    audience: &'a str,
    signed: bool,
}

/// A response with one assertion, signed by the test identity provider, in canonical form.
fn respond(a: &Answer<'_>) -> Result<String, Error> {
    let (start, end) = (instant(now() - 10), instant(now() + 300));
    let values: String = a
        .groups
        .iter()
        .map(|g| format!("<saml:AttributeValue>{g}</saml:AttributeValue>"))
        .collect();
    // One assertion per request, so each answer's ID is its own.
    let id = format!("_a{}", a.request.trim_start_matches('_'));
    let body = format!(
        r#"<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{req}" NotOnOrAfter="{end}" Recipient="{ACS}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{start}" NotOnOrAfter="{end}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="groups">{values}</saml:Attribute></saml:AttributeStatement></saml:Assertion>"#,
        email = a.email,
        req = &a.request,
        aud = a.audience,
    );
    let open = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{start}" Version="2.0"><saml:Issuer>{IDP}</saml:Issuer>"#
    );
    let digest = x509::base64_encode(
        ring::digest::digest(&ring::digest::SHA256, format!("{open}{body}").as_bytes()).as_ref(),
    );
    let info = |ns: &str| {
        format!(
            r##"<ds:SignedInfo{ns}><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        )
    };
    // As its own apex, SignedInfo carries the ds namespace it inherits from Signature.
    let canonical = info(r#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#);
    let der = gantry_core::config::pem_certificates(&KEY.replace("PRIVATE KEY", "CERTIFICATE"))
        .pop()
        .ok_or("no key")?;
    let pair = RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("{e:?}"))?;
    let mut sig = vec![0u8; pair.public().modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        canonical.as_bytes(),
        &mut sig,
    )
    .map_err(|e| format!("{e:?}"))?;
    let signature = if a.signed {
        format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>"#,
            info(""),
            x509::base64_encode(&sig)
        )
    } else {
        String::new()
    };
    Ok(format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS}" ID="_r1" InResponseTo="{req}" IssueInstant="{start}" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>{open}{signature}{body}</samlp:Response>"#,
        req = &a.request,
    ))
}

async fn post(
    s: &Setup,
    cookie: &str,
    relay: &str,
    xml: &str,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    send(
        &s.app,
        "POST",
        "/console/saml/acs",
        &format!("gantry_saml={cookie}"),
        &format!(
            "SAMLResponse={}&RelayState={}",
            enc(&x509::base64_encode(xml.as_bytes())),
            enc(relay)
        ),
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

fn last_refusal(s: &Setup) -> Result<String, Error> {
    let last = admin_records(s)?.pop().ok_or("no record")?;
    assert_eq!(last["action"], "console_sign_in");
    assert_eq!(last["target"]["via"], "saml");
    Ok(last["code"].as_str().unwrap_or("").to_string())
}

#[tokio::test]
async fn a_signed_assertion_signs_in_with_the_role_and_team_its_groups_give() -> TestResult {
    let s = setup("ok")?;
    // The sign-in page's single sign-on button leads to SAML when it is the only one set up.
    let (_, _, page) = send(&s.app, "GET", "/console/sign-in", "", "").await?;
    assert!(page.contains(r#"href="/console/sso/start""#), "{page}");
    let (status, headers, _) = send(&s.app, "GET", "/console/sso/start", "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/console/saml/start")
    );
    let (status, headers, metadata) = send(&s.app, "GET", "/console/saml/metadata", "", "").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/samlmetadata+xml")
    );
    assert!(
        metadata.contains(&format!(r#"entityID="{SP}""#)),
        "{metadata}"
    );
    assert!(
        metadata.contains(&format!(r#"Location="{ACS}""#)),
        "{metadata}"
    );

    let (id, cookie) = start(&s).await?;
    let xml = respond(&Answer {
        request: id.clone(),
        email: "Dana@Example.com",
        groups: &["gantry-admins", "payments-eng"],
        audience: SP,
        signed: true,
    })?;
    let (status, headers, body) = post(&s, &cookie, &id, &xml).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session = set_cookie(&headers, "gantry_console");
    assert_eq!(session.len(), 64);
    let (status, _, page) = send(
        &s.app,
        "GET",
        "/console/audit",
        &format!("gantry_console={session}"),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("dana@example.com"), "{page}");
    let signed_in = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(signed_in["verdict"], "allow");
    assert_eq!(signed_in["person"], "dana@example.com");
    assert_eq!(signed_in["team"], "payments");
    assert_eq!(signed_in["target"]["via"], "saml");
    assert_eq!(signed_in["target"]["role"], "admin");

    // The same answer again is a replay.
    let (status, _, _) = post(&s, &cookie, &id, &xml).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(last_refusal(&s)?, "saml_replay");
    Ok(())
}

#[tokio::test]
async fn unsigned_misdirected_unstarted_and_roleless_answers_are_refused() -> TestResult {
    let s = setup("refused")?;
    let answer = |id: &str| Answer {
        request: id.to_string(),
        email: "dana@example.com",
        groups: &["gantry-admins"],
        audience: SP,
        signed: true,
    };
    // Unsigned.
    let (id, cookie) = start(&s).await?;
    let request = id.as_str();
    let xml = respond(&Answer {
        signed: false,
        ..answer(request)
    })?;
    let (status, _, page) = post(&s, &cookie, request, &xml).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(page.contains("not signed"), "{page}");
    assert_eq!(last_refusal(&s)?, "saml_unsigned");
    // For another service provider.
    let (id, cookie) = start(&s).await?;
    let request = id.as_str();
    let xml = respond(&Answer {
        audience: "https://elsewhere.example.com",
        ..answer(request)
    })?;
    post(&s, &cookie, request, &xml).await?;
    assert_eq!(last_refusal(&s)?, "saml_audience");
    // Changed after it was signed.
    let (id, cookie) = start(&s).await?;
    let request = id.as_str();
    let xml = respond(&answer(request))?.replace("gantry-admins", "gantry-admin5");
    post(&s, &cookie, request, &xml).await?;
    assert_eq!(last_refusal(&s)?, "saml_signature");
    // Not started in this browser (no cookie), or started for another request.
    let (id, _) = start(&s).await?;
    let request = id.as_str();
    let xml = respond(&answer(request))?;
    post(&s, "", request, &xml).await?;
    assert_eq!(last_refusal(&s)?, "saml_replay");
    let (_, other_cookie) = start(&s).await?;
    post(&s, &other_cookie, request, &xml).await?;
    assert_eq!(last_refusal(&s)?, "saml_replay");
    // Signed and right, but no console role, or an email outside the allowed domains.
    let (id, cookie) = start(&s).await?;
    let request = id.as_str();
    let xml = respond(&Answer {
        groups: &["staff"],
        ..answer(request)
    })?;
    post(&s, &cookie, request, &xml).await?;
    assert_eq!(last_refusal(&s)?, "sso_role");
    let (id, cookie) = start(&s).await?;
    let request = id.as_str();
    let xml = respond(&Answer {
        email: "eve@elsewhere.com",
        ..answer(request)
    })?;
    post(&s, &cookie, request, &xml).await?;
    assert_eq!(last_refusal(&s)?, "sso_email");
    Ok(())
}

/// RFC 7636, appendix B: the verifier and its S256 challenge.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Runs the browser's side of a `gantry login` on a SAML-only setup, up to where it goes back to the CLI's
/// listener, and returns that address.
async fn cli_browse(s: &Setup, email: &str, groups: &[&str]) -> Result<String, Error> {
    let login = format!(
        "/console/cli/login?cli_port=1&cli_state=abcdefghijklmnop&cli_challenge={CHALLENGE}"
    );
    let (status, headers, body) = send(&s.app, "GET", &login, "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let to = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(to.starts_with("/console/saml/start?"), "{to}");
    assert_eq!(param(&to, "cli_challenge"), CHALLENGE);
    let (status, headers, body) = send(&s.app, "GET", &to, "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let idp = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let id = param(&idp, "RelayState");
    let (saml, cli) = (
        set_cookie(&headers, "gantry_saml"),
        set_cookie(&headers, "gantry_cli"),
    );
    assert!(!cli.is_empty(), "no gantry_cli cookie");
    let xml = respond(&Answer {
        request: id.clone(),
        email,
        groups,
        audience: SP,
        signed: true,
    })?;
    let (status, headers, body) = send(
        &s.app,
        "POST",
        "/console/saml/acs",
        &format!("gantry_saml={saml}; gantry_cli={cli}"),
        &format!(
            "SAMLResponse={}&RelayState={}",
            enc(&x509::base64_encode(xml.as_bytes())),
            enc(&id)
        ),
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    // Neither a console session nor the key: only a one-use code, for the CLI that holds the verifier.
    assert!(set_cookie(&headers, "gantry_console").is_empty());
    Ok(headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string())
}

#[tokio::test]
async fn gantry_login_over_saml_issues_a_key_in_the_team_the_groups_give() -> TestResult {
    let s = setup("cli")?;
    let back = cli_browse(&s, "Dana@Example.com", &["payments-eng"]).await?;
    assert!(
        back.starts_with("http://127.0.0.1:1/callback?state=abcdefghijklmnop&code="),
        "{back}"
    );
    let code = param(&back, "code");
    // Without the verifier the code is worth nothing, and is spent.
    let (status, _, _) = send(
        &s.app,
        "POST",
        "/console/cli/token",
        "",
        &format!("code={code}&verifier=wrong"),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let back = cli_browse(&s, "Dana@Example.com", &["payments-eng"]).await?;
    let (status, _, body) = send(
        &s.app,
        "POST",
        "/console/cli/token",
        "",
        &format!("code={}&verifier={VERIFIER}", param(&back, "code")),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let got: Value = serde_json::from_str(&body)?;
    assert_eq!(got["name"], "dana@example.com");
    assert_eq!(got["team"], "payments");
    let key = got["key"].as_str().unwrap_or("");
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    assert!(
        keys.contains(&format!(
            "  - name: dana@example.com\n    team: payments\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )),
        "{keys}"
    );
    let issued = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(issued["action"], "self_issue_key");
    assert_eq!(issued["team"], "payments");
    Ok(())
}

#[tokio::test]
async fn gantry_login_over_saml_refuses_who_self_issue_or_the_teams_do_not_place() -> TestResult {
    let s = setup("cli-refused")?;
    // Teams place people by group, so a person in none of them gets no key, and the CLI is told why.
    let back = cli_browse(&s, "dana@example.com", &["staff"]).await?;
    assert!(back.contains("error=sso_team"), "{back}");
    let last = admin_records(&s)?.pop().ok_or("no record")?;
    assert_eq!(last["code"], "sso_team");
    assert_eq!(last["target"]["via"], "saml");
    // With no self_issue under console.saml, gantry login is off.
    let path = s.dir.join("gantry.policy.yaml");
    let text = std::fs::read_to_string(&path)?;
    std::fs::write(
        &path,
        text.replace(
            "    self_issue:\n      allowed_domains: [example.com]\n",
            "",
        ),
    )?;
    let login = format!(
        "/console/saml/start?cli_port=1&cli_state=abcdefghijklmnop&cli_challenge={CHALLENGE}"
    );
    let (status, _, body) = send(&s.app, "GET", &login, "", "").await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("console.saml.self_issue"), "{body}");
    Ok(())
}

#[test]
fn a_saml_section_without_a_usable_certificate_or_acs_is_refused_with_the_fix() -> TestResult {
    let s = setup("check")?;
    let path = s.dir.join("gantry.policy.yaml");
    let text = std::fs::read_to_string(&path)?;
    let broken = text
        .replace("BEGIN CERTIFICATE", "BEGIN NOTHING")
        .replace(ACS, "https://gantry.example.com/elsewhere");
    std::fs::write(&path, broken)?;
    let errors = gantry_core::config::load(&path, None)
        .err()
        .ok_or("loaded")?
        .join("\n");
    assert!(errors.contains("idp_certificate must be"), "{errors}");
    assert!(errors.contains("acs_url must be"), "{errors}");
    Ok(())
}
