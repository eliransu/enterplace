//! JWTs from a customer's identity provider, accepted on the model routes in place of a Enterplace key. The policy's
//! `jwt:` list names each trusted issuer, the audience its tokens must carry, where its signing keys are, and which
//! claims name the person and the team. A verified token is decided and recorded as that person.
//!
//! Every check fails closed: an unknown issuer, an unknown key, a wrong signature, audience or time, or a claim that
//! is missing or not a name is a refusal, never a pass.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::body::Body;
use enterplace_core::{
    config::valid_name,
    id,
    policy::{JwtIdentity, JwtTrust, Principal},
};
use http_body_util::{BodyExt, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::Value;

/// How long an issuer's keys are used before they are fetched again.
const CACHE: Duration = Duration::from_secs(10 * 60);
/// A token signed with a key not in the cache fetches the keys again, at most this often per issuer, so a flood of
/// tokens with made-up key IDs cannot make Enterplace hammer the identity provider.
const REFETCH_AFTER: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(10);
/// No key set is near this size.
const MAX_BODY: usize = 1024 * 1024;
/// Clock difference allowed between Enterplace and the identity provider for `exp` and `nbf`.
const LEEWAY: u64 = 60;

/// Why a token was refused: a code and a message naming the cause and the fix.
pub(crate) struct Refused {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    /// The identity provider could not be reached: the refusal may clear by itself.
    pub(crate) unavailable: bool,
}

fn refused(code: &'static str, message: impl Into<String>) -> Refused {
    Refused {
        code,
        message: message.into(),
        unavailable: false,
    }
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
    key: Key,
}

/// One issuer's keys and when they were fetched.
type Fetched = (Instant, Arc<Vec<Jwk>>);

/// The signing keys of each issuer, by key set URL, with when they were fetched. One per server, kept across reloads.
#[derive(Default)]
pub(crate) struct Keys {
    sets: Mutex<HashMap<String, Fetched>>,
}

/// Whether a credential is shaped like a JWT: three base64url parts, the first a JSON object. Enterplace keys never are.
pub(crate) fn looks_like(token: &str) -> bool {
    token.starts_with("eyJ") && token.split('.').count() == 3
}

/// Checks `token` against the trusted issuers and returns who it names.
pub(crate) async fn verify(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    keys: &Keys,
    trusts: &[JwtTrust],
    token: &str,
) -> Result<Principal, Refused> {
    verified(client, keys, trusts, token)
        .await
        .map(|(person, _, _)| person)
}

/// Checks `token` for the admin API: who it names, with the role the issuer's `role_claim` gives them, the first of
/// `roles` whose `sso_values` hold one of the claim's values. A token with no such role is refused (`not_admin`).
pub(crate) async fn verify_admin(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    keys: &Keys,
    trusts: &[JwtTrust],
    roles: &[enterplace_core::policy::Role],
    token: &str,
) -> Result<Principal, Refused> {
    let (mut person, claims, trust) = verified(client, keys, trusts, token).await?;
    let Some(claim) = &trust.role_claim else {
        return Err(refused(
            "not_admin",
            format!(
                "Refused: tokens from \"{}\" are not accepted on the admin API, because its jwt: entry in the policy has no role_claim. Ask a Enterplace admin to set role_claim (for example groups) and list your group under a role's sso_values, or use an admin key.",
                trust.issuer
            ),
        ));
    };
    let values: Vec<&str> = match claims.get(claim) {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let role = roles
        .iter()
        .find(|r| r.sso_values.iter().any(|v| values.contains(&v.as_str())))
        .ok_or_else(|| {
            refused(
                "not_admin",
                format!(
                    "Refused: the token's \"{claim}\" claim holds none of the values in a role's sso_values, so \"{}\" has no admin role. Ask a Enterplace admin to add your group to a role under roles: in the policy.",
                    person.name
                ),
            )
        })?;
    person.role = Some(role.name.clone());
    Ok(person)
}

/// Checks `token` against the trusted issuers: who it names, its claims, and the issuer that signed it.
async fn verified<'t>(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    keys: &Keys,
    trusts: &'t [JwtTrust],
    token: &str,
) -> Result<(Principal, Value, &'t JwtTrust), Refused> {
    let bad = |what: &str| {
        refused(
            "jwt_invalid",
            format!(
                "Refused: the bearer token is not a well formed JWT: {what}. Send a token from your identity provider, or your Enterplace key."
            ),
        )
    };
    let parts: Vec<&str> = token.split('.').collect();
    let [head, body, sig] = parts[..] else {
        return Err(bad("it does not have three parts"));
    };
    let json =
        |part: &str| b64url_decode(part).and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let header = json(head).ok_or_else(|| bad("its header is not base64url JSON"))?;
    let claims = json(body).ok_or_else(|| bad("its claims are not base64url JSON"))?;
    let sig = b64url_decode(sig).ok_or_else(|| bad("its signature is not base64url"))?;
    let text = |name: &str| claims.get(name).and_then(Value::as_str).unwrap_or("");
    // The issuer is read before the signature is checked only to pick whose keys check it.
    let issuer = text("iss");
    let Some(trust) = trusts.iter().find(|t| t.issuer == issuer) else {
        return Err(refused(
            "jwt_untrusted",
            format!(
                "Refused: the token was issued by \"{issuer}\", which this gateway's policy does not trust. Ask a Enterplace admin to add it under jwt:, or send your Enterplace key."
            ),
        ));
    };
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != "RS256" && alg != "ES256" {
        return Err(refused(
            "jwt_invalid",
            format!(
                "Refused: the token is signed with \"{alg}\". Enterplace accepts RS256 and ES256 only. Set your identity provider to sign access tokens with one of them."
            ),
        ));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let signed = &token.as_bytes()[..head.len() + 1 + body.len()];
    let mut set = keys.get(client, &trust.jwks_url, false).await?;
    if pick(&set, alg, kid).is_none() {
        // The issuer may have rotated its keys since they were fetched.
        set = keys.get(client, &trust.jwks_url, true).await?;
    }
    let key = pick(&set, alg, kid).ok_or_else(|| {
        refused(
            "jwt_invalid",
            format!(
                "Refused: the token was signed with key \"{}\", which is not in {}'s key set at {}. If the issuer just rotated its keys, try again in a minute; otherwise the token did not come from this issuer.",
                kid.unwrap_or("(none named)"),
                trust.issuer,
                trust.jwks_url
            ),
        )
    })?;
    let ok = match &key.key {
        Key::Rsa { n, e } => RsaPublicKeyComponents { n, e }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, signed, &sig)
            .is_ok(),
        Key::Ec(point) => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(signed, &sig)
            .is_ok(),
    };
    if !ok {
        return Err(refused(
            "jwt_invalid",
            "Refused: the token's signature does not match its issuer's key, so it was changed or forged. Get a new token from your identity provider.",
        ));
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(aud)) => *aud == trust.audience,
        Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(&trust.audience)),
        _ => false,
    };
    if !audience_ok {
        return Err(refused(
            "jwt_invalid",
            format!(
                "Refused: the token is not for this gateway: its audience is not \"{}\". Ask your identity provider for a token with that audience.",
                trust.audience
            ),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let Some(exp) = claims.get("exp").and_then(Value::as_u64) else {
        return Err(bad(
            "it has no exp, and a token that never expires is not accepted",
        ));
    };
    if exp + LEEWAY <= now {
        return Err(refused(
            "jwt_expired",
            "Refused: the token has expired. Get a new one from your identity provider; if it repeats, check this machine's clock.",
        ));
    }
    if claims
        .get("nbf")
        .and_then(Value::as_u64)
        .is_some_and(|nbf| nbf > now + LEEWAY)
    {
        return Err(refused(
            "jwt_invalid",
            "Refused: the token is not valid yet (nbf). Check the clocks of this machine and the identity provider.",
        ));
    }
    let name_in = |claim: &str| -> Result<String, Refused> {
        let value = match claims.get(claim) {
            Some(Value::String(v)) => Some(v.clone()),
            // A group claim is often a list: one value is unambiguous, several are not guessed at.
            Some(Value::Array(list)) if list.len() == 1 => list[0].as_str().map(str::to_string),
            _ => None,
        };
        value.filter(|v| valid_name(v)).ok_or_else(|| {
            refused(
                "jwt_claims",
                format!(
                    "Refused: the token's \"{claim}\" claim is missing, holds more than one value, or is not a name (letters, digits, dots, dashes, underscores and @, at most 100 characters). Ask a Enterplace admin to check jwt: in the policy against your identity provider's tokens."
                ),
            )
        })
    };
    let name = name_in(&trust.person_claim)?;
    let team = match (&trust.team_claim, &trust.team) {
        (Some(claim), _) => name_in(claim)?,
        (None, Some(team)) => team.clone(),
        (None, None) => return Err(bad("the policy names no team for this issuer")),
    };
    let subject = text("sub").to_string();
    let person = Principal {
        name,
        team,
        admin: false,
        // Records and per-key counters name the identity the way they name a key: by 8 hex characters.
        key: id::sha256_hex(format!("{issuer}\n{subject}").as_bytes())[..8].to_string(),
        jwt: Some(JwtIdentity {
            issuer: issuer.to_string(),
            subject,
        }),
        ..Principal::default()
    };
    Ok((person, claims, trust))
}

/// The one key that can check this token: by its kid, or the only key of the right type when it names none.
fn pick<'a>(set: &'a [Jwk], alg: &str, kid: Option<&str>) -> Option<&'a Jwk> {
    let candidates: Vec<&Jwk> = set
        .iter()
        .filter(|k| {
            matches!(
                (&k.key, alg),
                (Key::Rsa { .. }, "RS256") | (Key::Ec(_), "ES256")
            )
        })
        .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
        .collect();
    match candidates[..] {
        [one] => Some(one),
        _ => None,
    }
}

impl Keys {
    async fn get(
        &self,
        client: &Client<HttpsConnector<HttpConnector>, Body>,
        url: &str,
        fresh: bool,
    ) -> Result<Arc<Vec<Jwk>>, Refused> {
        let cached = self
            .sets
            .lock()
            .ok()
            .and_then(|sets| sets.get(url).map(|(at, set)| (*at, set.clone())));
        if let Some((at, set)) = &cached {
            let wait = if fresh { REFETCH_AFTER } else { CACHE };
            if at.elapsed() < wait {
                return Ok(set.clone());
            }
        }
        match fetch(client, url).await {
            Ok(set) => {
                let set = Arc::new(set);
                if let Ok(mut sets) = self.sets.lock() {
                    sets.insert(url.to_string(), (Instant::now(), set.clone()));
                }
                Ok(set)
            }
            // A provider that is briefly away leaves the keys already known in use.
            Err(_) if cached.is_some() => Ok(cached.map(|(_, set)| set).unwrap_or_default()),
            Err(err) => Err(Refused {
                code: "jwt_keys_unavailable",
                message: format!(
                    "Refused: Enterplace could not read the identity provider's signing keys ({err}), so it cannot check the token. Try again; if it repeats, tell your Enterplace admin to check jwks_url in the policy."
                ),
                unavailable: true,
            }),
        }
    }
}

async fn fetch(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    url: &str,
) -> Result<Vec<Jwk>, String> {
    let request = axum::http::Request::get(url)
        .header(axum::http::header::ACCEPT, "application/json")
        .body(Body::empty())
        .map_err(|err| format!("{url} is not a URL: {err}"))?;
    let response = tokio::time::timeout(TIMEOUT, client.request(request))
        .await
        .map_err(|_| format!("{url} did not answer within {} seconds", TIMEOUT.as_secs()))?
        .map_err(|_| format!("{url} could not be reached"))?;
    if !response.status().is_success() {
        return Err(format!(
            "{url} answered HTTP {}",
            response.status().as_u16()
        ));
    }
    let body = tokio::time::timeout(
        TIMEOUT,
        Limited::new(response.into_body(), MAX_BODY).collect(),
    )
    .await
    .map_err(|_| format!("{url} stopped sending"))?
    .map_err(|_| format!("{url} sent an answer that could not be read"))?
    .to_bytes();
    let doc: Value =
        serde_json::from_slice(&body).map_err(|_| format!("{url} did not answer with JSON"))?;
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
                key,
            })
        })
        .collect())
}

// ponytail: the console's sso module has the same decoder; it is private to that crate, and sharing it means a
// public JWT module in enterplace-core once a third user appears.
/// Base64url without padding, as JWTs and JWKs use it.
fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
