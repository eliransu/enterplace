//! Console sign-in through an OpenID Connect provider: the authorization code flow with PKCE, state and nonce.
//!
//! Every check fails closed. A refusal carries a code for the audit record and a message that names the cause
//! and the fix, shown on the sign-in page.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    http::{Request, header},
};
use enterplace_core::config::{Sso, secure_url};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::Value;

use crate::html::enc;

/// Why a sign-in was refused: a code for the audit record, and the message for the person.
pub(crate) struct Refusal {
    pub code: &'static str,
    pub message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

/// How long discovery and keys are trusted before they are fetched again. A token signed with a key not in
/// the cache fetches the keys at once, so a provider that rotates its keys is followed without waiting.
pub(crate) const CACHE: Duration = Duration::from_secs(10 * 60);
const TIMEOUT: Duration = Duration::from_secs(10);
/// No provider document is near this size; a larger one is refused instead of read into memory.
const MAX_BODY: usize = 1024 * 1024;
/// Clock difference allowed between Enterplace and the provider when checking `exp`.
const LEEWAY: u64 = 60;

pub(crate) type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub(crate) fn client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(TIMEOUT));
    connector.enforce_http(false);
    // Two rustls providers are in the build (ring and posthog-rs's aws-lc-rs), so name ring or rustls panics.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    Client::builder(TokioExecutor::new()).build(connector)
}

enum Key {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// The uncompressed P-256 point: 0x04, then x, then y.
    Ec(Vec<u8>),
}

struct Jwk {
    kid: Option<String>,
    alg: Option<String>,
    key: Key,
}

/// What discovery says about the provider, and its signing keys.
pub(crate) struct Provider {
    pub issuer: String,
    pub fetched: Instant,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// client_secret_post when the provider does not take client_secret_basic, the default in OpenID Connect.
    secret_in_body: bool,
    keys: Vec<Jwk>,
}

pub(crate) async fn fetch(
    client: &HttpClient,
    request: Request<Full<Bytes>>,
    what: &str,
) -> Result<(u16, Value), String> {
    let uri = request.uri().to_string();
    let response = tokio::time::timeout(TIMEOUT, client.request(request))
        .await
        .map_err(|_| {
            format!(
                "{what} at {uri} did not answer within {} seconds",
                TIMEOUT.as_secs()
            )
        })?
        .map_err(|err| format!("{what} at {uri} could not be reached: {err}"))?;
    let status = response.status().as_u16();
    let body = tokio::time::timeout(
        TIMEOUT,
        Limited::new(response.into_body(), MAX_BODY).collect(),
    )
    .await
    .map_err(|_| format!("{what} at {uri} stopped sending"))?
    .map_err(|err| format!("{what} at {uri} sent an answer that could not be read: {err}"))?
    .to_bytes();
    let value = serde_json::from_slice(&body).map_err(|_| {
        format!("{what} at {uri} answered HTTP {status} with something that is not JSON")
    })?;
    Ok((status, value))
}

fn get(url: &str) -> Result<Request<Full<Bytes>>, String> {
    Request::get(url)
        .header(header::ACCEPT, "application/json")
        .body(Full::default())
        .map_err(|err| format!("{url} is not a URL Enterplace can call: {err}"))
}

/// Reads the provider's discovery document and its keys.
pub(crate) async fn discover(client: &HttpClient, sso: &Sso) -> Result<Provider, Refusal> {
    let unreachable = |err: String| {
        refuse(
            "sso_provider",
            format!(
                "Single sign-on is unavailable: {err}. Check that the issuer in the policy file is right and that Enterplace can reach it, then try again."
            ),
        )
    };
    let url = format!(
        "{}/.well-known/openid-configuration",
        sso.issuer.trim_end_matches('/')
    );
    let (status, doc) = fetch(
        client,
        get(&url).map_err(unreachable)?,
        "The provider's discovery document",
    )
    .await
    .map_err(unreachable)?;
    if status != 200 {
        return Err(unreachable(format!("{url} answered HTTP {status}")));
    }
    let text = |key: &str| {
        doc.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    // OpenID Connect Discovery 1.0, section 4.3: the document must name the issuer it was fetched for.
    if text("issuer") != sso.issuer {
        return Err(refuse(
            "sso_issuer",
            format!(
                "The provider's discovery document names issuer \"{}\", not \"{}\". Copy the issuer exactly as the provider writes it into console.sso.issuer.",
                text("issuer"),
                sso.issuer
            ),
        ));
    }
    let (authorization_endpoint, token_endpoint, jwks_uri) = (
        text("authorization_endpoint"),
        text("token_endpoint"),
        text("jwks_uri"),
    );
    for (name, value) in [
        ("authorization_endpoint", &authorization_endpoint),
        ("token_endpoint", &token_endpoint),
        ("jwks_uri", &jwks_uri),
    ] {
        if !secure_url(value) {
            return Err(refuse(
                "sso_provider",
                format!(
                    "The provider's discovery document gives {name} \"{value}\", which is not an https URL. Enterplace sends the client secret and trusts keys only over https. Fix the provider's settings."
                ),
            ));
        }
    }
    let list = |key: &str| {
        doc.get(key).and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
    };
    if list("code_challenge_methods_supported").is_some_and(|m| !m.iter().any(|m| m == "S256")) {
        return Err(refuse(
            "sso_provider",
            "The provider does not offer PKCE with S256, which Enterplace requires. Turn on PKCE for the console's app registration.",
        ));
    }
    let secret_in_body = list("token_endpoint_auth_methods_supported").is_some_and(|m| {
        !m.iter().any(|m| m == "client_secret_basic") && m.iter().any(|m| m == "client_secret_post")
    });
    let keys = jwks(client, &jwks_uri).await?;
    Ok(Provider {
        issuer: sso.issuer.clone(),
        fetched: Instant::now(),
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        secret_in_body,
        keys,
    })
}

async fn jwks(client: &HttpClient, url: &str) -> Result<Vec<Jwk>, Refusal> {
    let unreachable = |err: String| {
        refuse(
            "sso_provider",
            format!(
                "The provider's signing keys could not be read: {err}. Try again; if it repeats, check the provider."
            ),
        )
    };
    let (status, doc) = fetch(
        client,
        get(url).map_err(unreachable)?,
        "The provider's key set",
    )
    .await
    .map_err(unreachable)?;
    if status != 200 {
        return Err(unreachable(format!("{url} answered HTTP {status}")));
    }
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Keys of other types, curves or uses are skipped: a token signed with one is refused as an unknown key.
    Ok(keys
        .iter()
        .filter(|k| {
            k.get("use")
                .and_then(Value::as_str)
                .is_none_or(|u| u == "sig")
        })
        .filter_map(|k| {
            let s = |name: &str| k.get(name).and_then(Value::as_str);
            let b = |name: &str| s(name).and_then(b64url_decode);
            let key = match (s("kty")?, s("crv")) {
                ("RSA", _) => Key::Rsa {
                    n: b("n")?,
                    e: b("e")?,
                },
                ("EC", Some("P-256")) => {
                    let (x, y) = (b("x")?, b("y")?);
                    if x.len() != 32 || y.len() != 32 {
                        return None;
                    }
                    Key::Ec([&[4u8][..], &x, &y].concat())
                }
                _ => return None,
            };
            Some(Jwk {
                kid: s("kid").map(str::to_string),
                alg: s("alg").map(str::to_string),
                key,
            })
        })
        .collect())
}

/// The address the browser is sent to, to sign in at the provider.
pub(crate) fn authorize_url(
    provider: &Provider,
    sso: &Sso,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let challenge =
        b64url(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    let join = if provider.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{join}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256",
        provider.authorization_endpoint,
        enc(&sso.client_id),
        enc(&sso.redirect_url),
        enc(&sso.scopes.join(" "))
    )
}

/// Trades the code for the ID token at the token endpoint.
pub(crate) async fn exchange(
    client: &HttpClient,
    provider: &Provider,
    sso: &Sso,
    secret: &str,
    code: &str,
    verifier: &str,
) -> Result<String, Refusal> {
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={verifier}",
        enc(code),
        enc(&sso.redirect_url)
    );
    let mut request = Request::post(&provider.token_endpoint)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json");
    if provider.secret_in_body {
        form.push_str(&format!(
            "&client_id={}&client_secret={}",
            enc(&sso.client_id),
            enc(secret)
        ));
    } else {
        // RFC 6749 section 2.3.1: both parts are form encoded before they are joined.
        let basic = base64(
            format!("{}:{}", enc(&sso.client_id), enc(secret)).as_bytes(),
            STANDARD,
            true,
        );
        request = request.header(header::AUTHORIZATION, format!("Basic {basic}"));
    }
    let failed = |err: String| {
        refuse(
            "sso_token",
            format!(
                "The sign-in code could not be traded for an ID token: {err}. Start again from the sign-in page."
            ),
        )
    };
    let request = request
        .body(Full::new(Bytes::from(form)))
        .map_err(|err| failed(err.to_string()))?;
    let (status, body) = fetch(client, request, "The provider's token endpoint")
        .await
        .map_err(failed)?;
    if status != 200 {
        let said = |key: &str| {
            body.get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        return Err(refuse(
            "sso_token",
            format!(
                "The provider refused to give an ID token (HTTP {status}, {} {}). Check that client_id, the secret in {} and redirect_url match the console's app registration, then start again.",
                said("error"),
                said("error_description"),
                sso.client_secret_env
            ),
        ));
    }
    body.get("id_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| refuse("sso_token", "The provider's answer had no ID token. Make sure the console's app registration asks for the openid scope."))
}

/// Checks an ID token's signature and claims, and returns its claims.
/// `sso_unknown_key` means no key in the set matches: the caller fetches the keys again and retries once.
pub(crate) fn verify(
    token: &str,
    provider: &Provider,
    sso: &Sso,
    nonce: &str,
) -> Result<Value, Refusal> {
    let bad = |what: &str| {
        refuse(
            "sso_token",
            format!(
                "The ID token is not a well formed JWT: {what}. Start again; if it repeats, check the provider."
            ),
        )
    };
    let parts: Vec<&str> = token.split('.').collect();
    let [head, body, sig] = parts[..] else {
        return Err(bad("it does not have three parts"));
    };
    let header: Value = b64url_decode(head)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| bad("its header is not base64url JSON"))?;
    let sig = b64url_decode(sig).ok_or_else(|| bad("its signature is not base64url"))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != "RS256" && alg != "ES256" {
        return Err(refuse(
            "sso_signature",
            format!(
                "The ID token is signed with \"{alg}\". Enterplace accepts RS256 and ES256 only. Set the console's app registration to sign ID tokens with one of them."
            ),
        ));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let candidates: Vec<&Jwk> = provider
        .keys
        .iter()
        .filter(|k| {
            matches!(
                (&k.key, alg),
                (Key::Rsa { .. }, "RS256") | (Key::Ec(_), "ES256")
            )
        })
        .filter(|k| k.alg.as_deref().is_none_or(|a| a == alg))
        .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
        .collect();
    // With no kid, a single key of the right type is unambiguous; more than one is not guessed at.
    let [key] = candidates[..] else {
        return Err(refuse(
            "sso_unknown_key",
            format!(
                "The ID token was signed with key \"{}\", which is not in the provider's key set at {}. If the provider just rotated its keys, try again; otherwise the token did not come from this issuer.",
                kid.unwrap_or("(none named)"),
                provider.jwks_uri
            ),
        ));
    };
    let signed = &token.as_bytes()[..head.len() + 1 + body.len()];
    let ok = match &key.key {
        Key::Rsa { n, e } => RsaPublicKeyComponents { n, e }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, signed, &sig)
            .is_ok(),
        Key::Ec(point) => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(signed, &sig)
            .is_ok(),
    };
    if !ok {
        return Err(refuse(
            "sso_signature",
            "The ID token's signature does not match the provider's key, so it was refused. Start again; if it repeats, the token was changed on the way or the issuer is wrong.",
        ));
    }
    let claims: Value = b64url_decode(body)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| bad("its claims are not base64url JSON"))?;
    let claim = |name: &str| claims.get(name).and_then(Value::as_str).unwrap_or("");
    if !issuer_matches(claim("iss"), &sso.issuer) {
        return Err(refuse(
            "sso_issuer",
            format!(
                "The ID token was issued by \"{}\", not \"{}\". Check console.sso.issuer in the policy file.",
                claim("iss"),
                sso.issuer
            ),
        ));
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(aud)) => *aud == sso.client_id,
        // OpenID Connect Core 3.1.3.7: with several audiences, azp must name this client.
        Some(Value::Array(auds)) => {
            auds.iter().any(|a| a.as_str() == Some(&sso.client_id))
                && (auds.len() == 1 || claim("azp") == sso.client_id)
        }
        _ => false,
    };
    if !audience_ok
        || claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(&sso.client_id))
    {
        return Err(refuse(
            "sso_audience",
            format!(
                "The ID token was issued for another app, not client \"{}\". Check console.sso.client_id against the console's app registration.",
                sso.client_id
            ),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let exp = claims.get("exp").and_then(Value::as_u64).unwrap_or(0);
    if exp + LEEWAY <= now {
        return Err(refuse(
            "sso_expired",
            "The ID token has expired. Start again from the sign-in page; if it repeats, check that this machine's clock is right.",
        ));
    }
    if claim("nonce") != nonce || nonce.is_empty() {
        return Err(refuse(
            "sso_nonce",
            "The ID token's nonce does not match the one this sign-in sent, so it may be replayed. Start again from the sign-in page.",
        ));
    }
    Ok(claims)
}

/// Whether an ID token's `iss` names the configured issuer. Exact, except that Google documents the `iss` of its
/// ID tokens as either `https://accounts.google.com` or `accounts.google.com`.
fn issuer_matches(iss: &str, issuer: &str) -> bool {
    iss == issuer || (issuer == "https://accounts.google.com" && iss == "accounts.google.com")
}

/// The verified email of the claims, lower case.
fn verified_email(claims: &Value) -> Result<String, (Option<String>, Refusal)> {
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if email.is_empty() {
        return Err((
            None,
            refuse(
                "sso_email",
                "The ID token has no email. Add the email scope or claim to the console's app registration.",
            ),
        ));
    }
    if claims.get("email_verified") == Some(&Value::Bool(false)) {
        return Err((
            Some(email),
            refuse(
                "sso_email",
                "The provider says this email is not verified. Verify it at the provider, then sign in again.",
            ),
        ));
    }
    Ok(email)
}

fn listed(email: &str, emails: &[String], domains: &[String]) -> bool {
    let domain = email.rsplit_once('@').map_or("", |(_, d)| d);
    emails.iter().any(|e| e == email) || domains.iter().any(|d| d == domain)
}

/// Who may sign in and with which role, as `console.sso` and `console.saml` both say it.
pub(crate) struct Access<'a> {
    /// Where it is set, for messages: `console.sso` or `console.saml`.
    pub section: &'static str,
    /// The claim or attribute whose values give the role, for messages.
    pub attribute: &'a str,
    pub allowed_domains: &'a [String],
    pub allowed_emails: &'a [String],
    pub admin_values: &'a [String],
    pub read_only_values: &'a [String],
}

impl<'a> Access<'a> {
    pub(crate) fn of_sso(sso: &'a Sso) -> Self {
        Access {
            section: "console.sso",
            attribute: &sso.role_claim,
            allowed_domains: &sso.allowed_domains,
            allowed_emails: &sso.allowed_emails,
            admin_values: &sso.admin_values,
            read_only_values: &sso.read_only_values,
        }
    }

    pub(crate) fn of_saml(saml: &'a enterplace_core::config::Saml) -> Self {
        Access {
            section: "console.saml",
            attribute: &saml.role_attribute,
            allowed_domains: &saml.allowed_domains,
            allowed_emails: &saml.allowed_emails,
            admin_values: &saml.admin_values,
            read_only_values: &saml.read_only_values,
        }
    }

    pub(crate) fn lets_in(&self, email: &str) -> bool {
        listed(email, self.allowed_emails, self.allowed_domains)
    }
}

/// The values of a claim that is a string or a list of strings.
pub(crate) fn values<'v>(claims: &'v Value, claim: &str) -> Vec<&'v str> {
    match claims.get(claim) {
        Some(Value::String(v)) => vec![v.as_str()],
        Some(Value::Array(vs)) => vs.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Whose personal key `enterplace login` may issue, under `console.sso.self_issue`, and in which team: the team of the
/// policy's `teams:` that lists the email or holds one of the person's group values, else `self_issue.team`. When
/// the teams place people and place this one nowhere, the key is refused unless `self_issue.team` is written. No
/// role is needed: the key is for the person's own requests, which the policy's rules decide.
pub(crate) fn admit_self(
    claims: &Value,
    sso: &Sso,
    teams: &[enterplace_core::policy::Team],
) -> Result<(String, String, u32), (Option<String>, Refusal)> {
    let email = verified_email(claims)?;
    let groups = values(claims, &sso.role_claim);
    admit_self_person(
        email,
        &groups,
        &Access::of_sso(sso),
        sso.self_issue.as_ref(),
        teams,
    )
}

/// [`admit_self`] for a person the identity provider vouched for, over OpenID Connect or SAML.
pub(crate) fn admit_self_person(
    email: String,
    groups: &[&str],
    access: &Access<'_>,
    self_issue: Option<&enterplace_core::config::SelfIssue>,
    teams: &[enterplace_core::policy::Team],
) -> Result<(String, String, u32), (Option<String>, Refusal)> {
    let Some(si) = self_issue else {
        let message = format!(
            "enterplace login is off: the policy file has no {}.self_issue section. Ask an admin to add one, or for a key.",
            access.section
        );
        return Err((Some(email), refuse("sso_self_issue", message)));
    };
    if !listed(&email, &si.allowed_emails, &si.allowed_domains) {
        let message = format!(
            "{email} may not get a key with enterplace login. Ask an admin to add it, or its domain, to {}.self_issue in the policy file, or for a key.",
            access.section
        );
        return Err((Some(email), refuse("sso_self_issue", message)));
    }
    let team = match enterplace_core::policy::team_of(teams, &email, groups) {
        Some(team) => team.name.clone(),
        None if si.team_set
            || teams
                .iter()
                .all(|t| t.members.is_empty() && t.sso_values.is_empty()) =>
        {
            si.team.clone()
        }
        None => {
            let message = format!(
                "{email} is in no team: the policy's teams list neither the email nor any of its \"{}\" values ({}). Ask an admin to add you to a team's members, or your group to a team's sso_values, in the policy file.",
                access.attribute,
                if groups.is_empty() {
                    "it has none".to_string()
                } else {
                    groups.join(", ")
                }
            );
            return Err((Some(email), refuse("sso_team", message)));
        }
    };
    Ok((email, team, si.expires_days))
}

/// Who the claims are, what role they get and their team, or why they are not let in.
pub(crate) fn admit(
    claims: &Value,
    sso: &Sso,
    roles: &[enterplace_core::policy::Role],
    teams: &[enterplace_core::policy::Team],
) -> Result<(String, String, String), (Option<String>, Refusal)> {
    let email = verified_email(claims)?;
    let groups = values(claims, &sso.role_claim);
    admit_person(email, &groups, &Access::of_sso(sso), roles, teams)
}

/// A person the identity provider vouched for, with its values of the role claim or attribute: their role and team,
/// or why they are not let in. The role is `admin` for an admin value, else the first policy role whose `sso_values`
/// holds one, else `read_only` for a read-only value. The team is the one `teams:` puts them in, else none.
pub(crate) fn admit_person(
    email: String,
    groups: &[&str],
    access: &Access<'_>,
    roles: &[enterplace_core::policy::Role],
    teams: &[enterplace_core::policy::Team],
) -> Result<(String, String, String), (Option<String>, Refusal)> {
    if !access.lets_in(&email) {
        let message = format!(
            "{email} may not sign in to this console. Ask an admin to add it, or its domain, to {} in the policy file.",
            access.section
        );
        return Err((Some(email), refuse("sso_email", message)));
    }
    let has = |list: &[String]| groups.iter().any(|v| list.iter().any(|l| l == v));
    let team = enterplace_core::policy::team_of(teams, &email, groups)
        .map(|t| t.name.clone())
        .unwrap_or_default();
    if has(access.admin_values) {
        Ok((email, "admin".into(), team))
    } else if let Some(role) = roles.iter().find(|r| has(&r.sso_values)) {
        Ok((email, role.name.clone(), team))
    } else if has(access.read_only_values) {
        Ok((email, "read_only".into(), team))
    } else {
        let message = format!(
            "{email} has no console role: its \"{}\" values hold none of the values in admin_values, read_only_values or a role's sso_values. Ask an admin to add you to the right group at the identity provider.",
            access.attribute
        );
        Err((Some(email), refuse("sso_role", message)))
    }
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(alphabet[(n >> (18 - 6 * i) & 63) as usize]));
        }
        if pad {
            out.push_str(&"=="[..3 - chunk.len()]);
        }
    }
    out
}

pub(crate) fn b64url(bytes: &[u8]) -> String {
    base64(bytes, URL_SAFE, false)
}

/// Base64url without padding, as JWTs and JWKs use it.
pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for byte in text.trim_end_matches('=').bytes() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_at_every_length() {
        for len in 0..10u8 {
            let bytes: Vec<u8> = (0..len).map(|i| i.wrapping_mul(97)).collect();
            assert_eq!(b64url_decode(&b64url(&bytes)), Some(bytes));
        }
        // RFC 4648 section 10.
        assert_eq!(base64(b"fooba", STANDARD, true), "Zm9vYmE=");
        assert_eq!(base64(b"foob", STANDARD, true), "Zm9vYg==");
        assert_eq!(b64url_decode("a+b"), None);
    }

    #[test]
    fn the_issuer_must_match_but_for_googles_two_documented_forms() {
        assert!(issuer_matches(
            "https://idp.example.com",
            "https://idp.example.com"
        ));
        assert!(!issuer_matches(
            "idp.example.com",
            "https://idp.example.com"
        ));
        assert!(!issuer_matches(
            "https://idp.example.com/",
            "https://idp.example.com"
        ));
        assert!(issuer_matches(
            "accounts.google.com",
            "https://accounts.google.com"
        ));
        assert!(!issuer_matches(
            "accounts.google.com.evil",
            "https://accounts.google.com"
        ));
    }
}
