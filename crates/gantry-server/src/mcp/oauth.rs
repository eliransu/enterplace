//! Sign-in, both ways.
//!
//! In: Gantry is an OAuth 2.1 authorization server for MCP clients, as the MCP authorization specification
//! describes: protected resource metadata (RFC 9728) named in every 401, authorization server metadata (RFC 8414),
//! dynamic client registration (RFC 7591), the authorization code grant with PKCE (S256 only), refresh tokens that
//! turn over on each use, and tokens bound to the resource they were asked for (RFC 8707). A person proves who they
//! are with their Gantry key, or with single sign-on through the console's identity provider (`console.sso`, with
//! `self_issue`, which decides who may have personal access). An access token is not a key: it names the person,
//! and every call made with it is checked and recorded as theirs, the key's kill switch included.
//!
//! Out: a server with `user_auth` runs each call with the caller's own credential, kept sealed. A person with none
//! is handed a one-use link (as MCP's URL mode elicitation) to give their header values or to sign in at the
//! server's own OAuth authorization server, which Gantry finds from the server's metadata and registers with.

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header, request::Parts},
    response::{IntoResponse, Response},
    routing::get,
};
use gantry_console::{Form, html};
use gantry_core::{id, mcp::UserAuth, policy::Policy, policy::Principal};
use serde_json::{Value, json};

use super::{Asked, Conn, Mcp, Shared, Upstream, event, keep::now};
use crate::Refusal;

/// The start of every access token Gantry issues to MCP clients, so it is told from a Gantry key at a glance.
const ACCESS_PREFIX: &str = "gantry_mcp_";
const REFRESH_PREFIX: &str = "gantry_mcpr_";
const ACCESS_FOR: u64 = 60 * 60;
const REFRESH_FOR: u64 = 30 * 24 * 60 * 60;
const CODE_FOR: u64 = 60;
/// How long a person has to finish signing in, here or at an upstream server.
const PENDING_FOR: u64 = 10 * 60;
/// Most an authorization server's JSON answer Gantry reads.
const MAX_JSON: usize = 1024 * 1024;

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route(
            "/.well-known/oauth-protected-resource/mcp/{bundle}",
            get(resource),
        )
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/register", axum::routing::post(register))
        .route("/oauth/authorize", get(authorize).post(authorize_key))
        .route("/oauth/token", axum::routing::post(token))
        .route("/oauth/connect/{id}", get(connect).post(connect_headers))
        .route("/oauth/callback", get(callback))
}

/// This Gantry as the caller reached it: the scheme (TLS here, or a proxy that says so) and the Host header.
pub(super) fn origin(parts: &Parts) -> String {
    let https = parts.extensions.get::<axum::http::uri::Scheme>().is_some()
        || parts.uri.scheme_str() == Some("https")
        || parts
            .headers
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"));
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        // Only what a host may hold: the origin goes into links and pages.
        .filter(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        })
        .unwrap_or("localhost");
    format!("{}://{host}", if https { "https" } else { "http" })
}

fn sha(text: &str) -> String {
    id::sha256_hex(text.as_bytes())
}

/// Base64url without padding, as PKCE writes a challenge.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// The S256 challenge of a PKCE verifier.
fn challenge(verifier: &str) -> String {
    b64url(&id::sha256(verifier.as_bytes()))
}

/// A page of Gantry's own, in the console's look, that no other site may frame.
fn page(status: StatusCode, title: &str, inner: &str) -> Response {
    let mut response = gantry_console::bare_page(status, title, inner);
    let headers = response.headers_mut();
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn notice(status: StatusCode, title: &str, text: &str) -> Response {
    page(
        status,
        title,
        &format!(r#"<p class="t-body">{}</p>"#, html::esc(text)),
    )
}

fn json_answer(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

fn oauth_error(error: &str, description: &str) -> Response {
    json_answer(
        StatusCode::BAD_REQUEST,
        &json!({"error": error, "error_description": description}),
    )
}

/// `url` with `pairs` added to its query, each value encoded.
fn with_query(url: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = url.to_string();
    for (i, (name, value)) in pairs.iter().enumerate() {
        let joint = if i == 0 && !url.contains('?') {
            '?'
        } else {
            '&'
        };
        out.push(joint);
        out.push_str(name);
        out.push('=');
        out.push_str(&html::enc(value));
    }
    out
}

/// A redirect URI a client may register: https, or http to this machine (RFC 8252), without a fragment.
fn redirect_ok(uri: &str) -> bool {
    uri.len() <= 2000
        && !uri.contains('#')
        && (uri.starts_with("https://") || gantry_core::config::secure_url(uri))
        && uri.parse::<Uri>().is_ok_and(|u| u.host().is_some())
}

/// Whether `asked` is one of the client's redirect URIs. A loopback one matches on any port, since a native client
/// picks a free port each time it signs in (RFC 8252 7.3).
fn redirect_registered(registered: &Value, asked: &str) -> bool {
    let without_port = |uri: &str| -> Option<String> {
        let u = uri.parse::<Uri>().ok()?;
        let host = u.host()?;
        let loopback = u.scheme_str() == Some("http")
            && (host == "127.0.0.1" || host == "[::1]" || host == "localhost");
        loopback.then(|| format!("{host}{}", u.path_and_query().map_or("/", |p| p.as_str())))
    };
    registered
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|r| {
            r == asked || (without_port(r).is_some() && without_port(r) == without_port(asked))
        })
}

async fn resource(State(mcp): State<Shared>, uri: Uri, headers: HeaderMap) -> Response {
    let base = origin_of(&headers);
    let path = uri
        .path()
        .strip_prefix("/.well-known/oauth-protected-resource")
        .filter(|p| !p.is_empty())
        .unwrap_or("/mcp");
    let _ = &mcp;
    json_answer(
        StatusCode::OK,
        &json!({
            "resource": format!("{base}{path}"),
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
            "resource_name": "Gantry MCP gateway",
        }),
    )
}

fn origin_of(headers: &HeaderMap) -> String {
    let mut parts = axum::http::Request::new(()).into_parts().0;
    parts.headers = headers.clone();
    origin(&parts)
}

async fn metadata(headers: HeaderMap) -> Response {
    let base = origin_of(&headers);
    json_answer(
        StatusCode::OK,
        &json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "token_endpoint": format!("{base}/oauth/token"),
            "registration_endpoint": format!("{base}/oauth/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
            "authorization_response_iss_parameter_supported": true,
        }),
    )
}

/// Dynamic client registration (RFC 7591), for public clients: Claude Desktop, Cursor, Claude Code and the like.
// ponytail: registration is open, as MCP clients expect, and each one is kept for good. Expire clients that never
// finished a sign-in when the table grows.
async fn register(State(mcp): State<Shared>, body: String) -> Response {
    let Ok(asked) = serde_json::from_str::<Value>(&body) else {
        return json_answer(
            StatusCode::BAD_REQUEST,
            &json!({"error": "invalid_client_metadata", "error_description": "The body must be a JSON object with redirect_uris."}),
        );
    };
    let uris: Vec<&str> = asked["redirect_uris"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if uris.is_empty() || uris.len() > 10 || !uris.iter().all(|u| redirect_ok(u)) {
        return json_answer(
            StatusCode::BAD_REQUEST,
            &json!({"error": "invalid_redirect_uri", "error_description": "redirect_uris must list 1 to 10 URIs, each https or http to this machine (127.0.0.1, [::1] or localhost), without a fragment."}),
        );
    }
    let client_id = format!("mcp_{}", id::random_hex(16));
    let name: String = asked["client_name"]
        .as_str()
        .unwrap_or("An MCP client")
        .chars()
        .take(100)
        .collect();
    let issued = now();
    let client = json!({"redirect_uris": uris, "client_name": name, "issued": issued});
    if let Err(err) = mcp.keep.put("client", &client_id, client).await {
        return json_answer(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "temporarily_unavailable", "error_description": format!("The client could not be kept: {err}. Try again.")}),
        );
    }
    json_answer(
        StatusCode::CREATED,
        &json!({
            "client_id": client_id,
            "client_id_issued_at": issued,
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }),
    )
}

/// The consent page: who asks, and the two ways to say who you are.
async fn authorize(State(mcp): State<Shared>, uri: Uri, headers: HeaderMap) -> Response {
    let query = Form::of(&uri);
    let base = origin_of(&headers);
    let client_id = query.get("client_id");
    let redirect_uri = query.get("redirect_uri");
    let client = match mcp.keep.get("client", client_id).await {
        Ok(Some(client)) if redirect_registered(&client["redirect_uris"], redirect_uri) => client,
        // Never redirect to a URI that is not the client's own: show the problem here instead.
        _ => {
            return notice(
                StatusCode::BAD_REQUEST,
                "This sign-in link does not work",
                "The MCP client that sent you here is not registered with this Gantry, or asked to send you back to an address it did not register. Remove the Gantry server from the client and add it again.",
            );
        }
    };
    let back = |error: &str, description: &str| {
        gantry_console::redirect(&with_query(
            redirect_uri,
            &[
                ("error", error),
                ("error_description", description),
                ("state", query.get("state")),
                ("iss", &base),
            ],
        ))
    };
    if query.get("response_type") != "code" {
        return back(
            "unsupported_response_type",
            "Gantry issues authorization codes only: send response_type=code.",
        );
    }
    let code_challenge = query.get("code_challenge");
    if query.get("code_challenge_method") != "S256" || code_challenge.len() != 43 {
        return back(
            "invalid_request",
            "Gantry requires PKCE with S256: send code_challenge and code_challenge_method=S256.",
        );
    }
    let resource = query.get("resource");
    if !resource.is_empty()
        && resource != format!("{base}/mcp")
        && !resource.starts_with(&format!("{base}/mcp/"))
    {
        return back(
            "invalid_target",
            "resource must be this Gantry's MCP endpoint, <gantry url>/mcp or /mcp/<bundle>.",
        );
    }
    let auth = id::random_hex(16);
    let verifier = id::random_hex(32);
    let pending = json!({
        "client_id": client_id,
        "client_name": client["client_name"],
        "redirect_uri": redirect_uri,
        "state": query.get("state"),
        "challenge": code_challenge,
        "resource": resource,
        "scope": query.get("scope"),
        "issuer": base,
        "sso_verifier": verifier,
        "exp": now() + PENDING_FOR,
    });
    if let Err(err) = mcp.keep.put("auth", &auth, pending).await {
        return notice(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sign-in is unavailable",
            &format!("Gantry could not keep this sign-in: {err}. Try again."),
        );
    }
    consent(
        &mcp,
        &auth,
        client["client_name"].as_str().unwrap_or_default(),
        &verifier,
        "",
    )
}

fn consent(mcp: &Mcp, auth: &str, client: &str, verifier: &str, error: &str) -> Response {
    let sso = if mcp.sso {
        let href = with_query(
            "/console/sso/cli/login",
            &[
                ("cli_port", "0"),
                ("cli_state", auth),
                ("cli_challenge", &challenge(verifier)),
            ],
        );
        format!(
            "<p>{}</p>",
            html::link(
                "Sign in with single sign-on",
                "primary",
                &html::esc(&href),
                false
            )
        )
    } else {
        String::new()
    };
    let field = html::field(&html::Field {
        id: "key",
        name: "key",
        label: "Your Gantry key",
        value: "",
        mono: true,
        extra: r#" type="password" autocomplete="off" required"#,
        hint: "The key stays here: the client gets a token that names you, for one hour at a time.",
        error,
    });
    let inner = format!(
        r#"<p class="t-body">{} asks to use the MCP tools this Gantry serves you, as you. Each call is checked against your policy rule and recorded under your name.</p>{sso}<form method="post" action="/oauth/authorize"><input type="hidden" name="auth" value="{}">{field}{}</form>"#,
        html::esc(client),
        html::esc(auth),
        html::button("Connect with my key", "", "submit", "")
    );
    page(
        if error.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        },
        "Connect an MCP client",
        &inner,
    )
}

/// The consent form, sent with the person's Gantry key.
async fn authorize_key(State(mcp): State<Shared>, headers: HeaderMap, body: String) -> Response {
    if !gantry_console::same_origin(&headers) {
        return gantry_console::foreign();
    }
    let form = Form::parse(&body);
    let auth_id = form.get("auth");
    let Ok(Some(auth)) = mcp.keep.get("auth", auth_id).await else {
        return notice(
            StatusCode::BAD_REQUEST,
            "This sign-in has ended",
            "It was finished already, or it is older than ten minutes. Start again from the MCP client.",
        );
    };
    let version = mcp.app.version();
    let known = version
        .policy
        .as_ref()
        .and_then(|p| p.identify(form.get("key")));
    let Some(person) = known.filter(|p| !p.expired(&gantry_core::audit::timestamp())) else {
        return consent(
            &mcp,
            auth_id,
            auth["client_name"].as_str().unwrap_or_default(),
            auth["sso_verifier"].as_str().unwrap_or_default(),
            "Gantry does not know this key, or it has expired. Paste the key you use with Gantry.",
        );
    };
    if mcp
        .keep
        .take("auth", auth_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return notice(
            StatusCode::BAD_REQUEST,
            "This sign-in has ended",
            "It was finished in another window. Start again from the MCP client.",
        );
    }
    let subject = json!({"via": "key", "key_sha256": sha(form.get("key")), "name": person.name, "team": person.team});
    mcp.issue_code(&auth, subject).await
}

impl Mcp {
    /// Ends a single sign-on started from the consent page: the console hands back who signed in.
    pub(super) async fn finish_sso(
        &self,
        console: &gantry_console::Console,
        state: &str,
        code: &str,
    ) -> Response {
        let Ok(Some(auth)) = self.keep.take("auth", state).await else {
            return notice(
                StatusCode::BAD_REQUEST,
                "This sign-in has ended",
                "It was finished already, or it is older than ten minutes. Start again from the MCP client.",
            );
        };
        let verifier = auth["sso_verifier"].as_str().unwrap_or_default();
        let Some((email, team)) = console.take_sign_in(code, verifier) else {
            return notice(
                StatusCode::BAD_REQUEST,
                "Single sign-on did not finish",
                "The sign-in code is unknown, used or older than two minutes. Start again from the MCP client.",
            );
        };
        let subject = json!({"via": "sso", "name": email, "team": team});
        self.issue_code(&auth, subject).await
    }

    /// A one-use authorization code for `subject`, and the browser sent back to the client with it.
    async fn issue_code(&self, auth: &Value, subject: Value) -> Response {
        let code = id::random_hex(32);
        let text = |f: &str| auth[f].as_str().unwrap_or_default().to_string();
        let kept = json!({
            "client_id": text("client_id"),
            "redirect_uri": text("redirect_uri"),
            "challenge": text("challenge"),
            "resource": text("resource"),
            "scope": text("scope"),
            "subject": subject,
            "exp": now() + CODE_FOR,
        });
        if let Err(err) = self.keep.put("code", &code, kept).await {
            return notice(
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign-in is unavailable",
                &format!("Gantry could not keep the sign-in code: {err}. Try again."),
            );
        }
        event(
            self,
            "mcp_oauth",
            json!({"action": "authorized", "person": subject["name"], "team": subject["team"], "via": subject["via"], "client_id": text("client_id"), "client_name": text("client_name")}),
        )
        .await;
        gantry_console::redirect(&with_query(
            &text("redirect_uri"),
            &[
                ("code", &code),
                ("state", &text("state")),
                ("iss", &text("issuer")),
            ],
        ))
    }

    /// Who a credential belongs to: a Gantry key, or an access token Gantry issued. Returns the person, the hash a
    /// key kill switch is matched with, and `oauth` for a token.
    pub(super) async fn authenticate(
        &self,
        policy: &Policy,
        headers: &HeaderMap,
        resource: &str,
        asked: &mut Asked,
    ) -> Result<(Principal, String, Option<&'static str>), Refusal> {
        let key = crate::caller_key(headers)?;
        let expired = |person: &Principal| {
            Refusal::new(
                StatusCode::UNAUTHORIZED,
                "key_expired",
                format!(
                    "Refused: the key {} of \"{}\" expired at {} (UTC). Ask a Gantry admin for a new key, or run gantry login again, and connect the MCP client again.",
                    person.key,
                    person.name,
                    person.expires.as_deref().unwrap_or_default()
                ),
            )
        };
        if let Some(person) = policy.identify(key) {
            asked.person = Some(person.clone());
            asked.key = Some(person.key.clone());
            if person.expired(&gantry_core::audit::timestamp()) {
                return Err(expired(person));
            }
            return Ok((person.clone(), sha(key), None));
        }
        let hash = sha(key);
        asked.key = Some(hash[..8].to_string());
        let unknown = || {
            Refusal::new(
                StatusCode::UNAUTHORIZED,
                "unknown_key",
                "Refused: Gantry does not know this key or token. It was never issued, it has been removed, or the token expired. Sign in again from the MCP client, or put your Gantry key in its headers as `Authorization: Bearer <key>`.",
            )
        };
        if !key.starts_with(ACCESS_PREFIX) {
            return Err(unknown());
        }
        let token = self
            .keep
            .get("token", &hash)
            .await
            .map_err(|err| {
                Refusal::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "store_unavailable",
                    format!("Refused: Gantry could not check this token: {err}. Try again, and tell your Gantry admin if it keeps failing."),
                )
            })?
            .ok_or_else(unknown)?;
        if let Some(bound) = token["resource"].as_str().filter(|r| !r.is_empty())
            && bound != resource
        {
            return Err(Refusal::new(
                StatusCode::UNAUTHORIZED,
                "wrong_resource",
                format!(
                    "Refused: this token was issued for {bound}, not {resource}. Sign in again from the MCP client for this address."
                ),
            ));
        }
        asked.oauth_client = token["client_id"].as_str().map(str::to_string);
        let subject = &token["subject"];
        let (person, kill) = match subject["via"].as_str() {
            Some("key") => {
                let sha256 = subject["key_sha256"].as_str().unwrap_or_default();
                // The key the person signed in with still decides: a removed key ends its tokens too.
                let person = policy
                    .entries()
                    .find(|(hash, _)| id::hex(hash.as_slice()) == sha256)
                    .map(|(_, p)| p.clone())
                    .ok_or_else(unknown)?;
                if person.expired(&gantry_core::audit::timestamp()) {
                    return Err(expired(&person));
                }
                (person, sha256.to_string())
            }
            Some("sso") => (
                Principal {
                    name: subject["name"].as_str().unwrap_or_default().to_string(),
                    team: subject["team"].as_str().unwrap_or_default().to_string(),
                    key: hash[..8].to_string(),
                    ..Principal::default()
                },
                hash.clone(),
            ),
            _ => return Err(unknown()),
        };
        asked.person = Some(person.clone());
        asked.key = Some(person.key.clone());
        Ok((person, kill, Some("oauth")))
    }

    /// Which session of `server` a call of `person` goes in, and the person's own credential when it needs one.
    /// `Err` when the person has not connected their account yet.
    pub(super) async fn conn(
        &self,
        server: &Upstream,
        person: &Principal,
        subject: Option<&str>,
    ) -> Result<Conn, Option<String>> {
        match self.conn_of(server, person, subject).await {
            Ok(conn) => Ok(conn),
            Err(why) => Err(why),
        }
    }

    /// The token `server` takes for the caller, traded for the token the caller holds (`subject`) at the identity
    /// provider's token endpoint: RFC 8693 token exchange, or the on-behalf-of flow. Kept until it expires.
    async fn exchange(
        &self,
        server: &Upstream,
        person: &Principal,
        subject: Option<&str>,
    ) -> Result<Conn, Option<String>> {
        let Some(UserAuth::Exchange {
            on_behalf_of,
            token_url,
            client_id,
            scopes,
            audience,
            resource,
            ..
        }) = &server.user_auth
        else {
            return Err(None);
        };
        let kind = if *on_behalf_of {
            "on_behalf_of"
        } else {
            "token_exchange"
        };
        let Some(subject) = subject else {
            return Err(Some(format!(
                "MCP server \"{}\" is reached with a token traded for yours, and this request carried none. Send the access token you hold at your identity provider in the {} header.",
                server.name,
                super::SUBJECT_HEADER
            )));
        };
        let key = sha(subject);
        let held = super::lock(&server.exchanged)
            .get(&key)
            .filter(|(_, exp)| *exp > now() + 30)
            .map(|(token, _)| token.clone());
        let token = match held {
            Some(token) => token,
            None => {
                let scope = scopes.join(" ");
                let mut pairs: Vec<(&str, &str)> = if *on_behalf_of {
                    vec![
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", subject),
                        ("requested_token_use", "on_behalf_of"),
                    ]
                } else {
                    vec![
                        (
                            "grant_type",
                            "urn:ietf:params:oauth:grant-type:token-exchange",
                        ),
                        ("subject_token", subject),
                        (
                            "subject_token_type",
                            "urn:ietf:params:oauth:token-type:access_token",
                        ),
                        (
                            "requested_token_type",
                            "urn:ietf:params:oauth:token-type:access_token",
                        ),
                    ]
                };
                pairs.push(("client_id", client_id));
                if let Some(secret) = &server.client_secret {
                    pairs.push(("client_secret", secret));
                }
                if !scope.is_empty() {
                    pairs.push(("scope", &scope));
                }
                if let Some(audience) = audience.as_deref().filter(|_| !on_behalf_of) {
                    pairs.push(("audience", audience));
                }
                if let Some(resource) = resource.as_deref().filter(|_| !on_behalf_of) {
                    pairs.push(("resource", resource));
                }
                let answer = self.post_form(token_url, &pairs).await.map_err(|err| {
                    Some(format!(
                        "MCP server \"{}\" is reached with a token traded for yours, and the identity provider did not trade it: {err}. Sign in again for a fresh token; if it keeps failing, a Gantry admin checks the server's token_url, oauth_client_id and audience.",
                        server.name
                    ))
                })?;
                let Some(token) = answer["access_token"].as_str() else {
                    return Err(Some(format!(
                        "MCP server \"{}\": the identity provider's answer to the token exchange holds no access_token. A Gantry admin checks the server's token_url.",
                        server.name
                    )));
                };
                let expires = now() + answer["expires_in"].as_u64().unwrap_or(300);
                let mut kept = super::lock(&server.exchanged);
                let at = now();
                kept.retain(|_, (_, exp)| *exp > at);
                if kept.len() < 10_000 {
                    kept.insert(key, (token.to_string(), expires));
                }
                token.to_string()
            }
        };
        let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| None)?;
        value.set_sensitive(true);
        Ok(Conn {
            key: person.name.clone(),
            headers: vec![(header::AUTHORIZATION, value)],
            auth: Some(kind),
        })
    }

    async fn conn_of(
        &self,
        server: &Upstream,
        person: &Principal,
        subject: Option<&str>,
    ) -> Result<Conn, Option<String>> {
        let Some(auth) = &server.user_auth else {
            return Ok(Conn::default());
        };
        if matches!(auth, UserAuth::Exchange { .. }) {
            return self.exchange(server, person, subject).await;
        }
        self.own(server, person, auth).await.map_err(|()| None)
    }

    /// The person's own credential, kept sealed since they connected their account.
    async fn own(
        &self,
        server: &Upstream,
        person: &Principal,
        auth: &UserAuth,
    ) -> Result<Conn, ()> {
        let id = format!("{}/{}", server.name, person.name);
        let name = sealed_name(&server.name, &person.name);
        let stored = match self.keep.get("cred", &id).await {
            Ok(Some(stored)) => stored,
            Ok(None) => return Err(()),
            Err(err) => {
                eprintln!(
                    "gantry: the MCP credential of \"{}\" for server \"{}\" could not be read: {err}",
                    person.name, server.name
                );
                return Err(());
            }
        };
        let mut opened: Value = self
            .keep
            .open(&name, stored["sealed"].as_str().unwrap_or_default())
            .ok()
            .and_then(|bytes: Vec<u8>| serde_json::from_slice(&bytes).ok())
            .ok_or(())?;
        let mut headers: Vec<(String, String)> = Vec::new();
        let kind = match auth {
            UserAuth::Headers(names) => {
                for header in names {
                    let value = opened["headers"][header.as_str()].as_str().ok_or(())?;
                    headers.push((header.clone(), value.to_string()));
                }
                "user_headers"
            }
            UserAuth::Exchange { .. } => return Err(()),
            UserAuth::OAuth { .. } => {
                let expires = opened["expires_at"].as_u64().unwrap_or(0);
                if expires > 0 && expires <= now() + 30 {
                    opened = self.refresh(server, person, &opened).await.ok_or(())?;
                }
                let access = opened["access_token"].as_str().ok_or(())?;
                headers.push(("authorization".to_string(), format!("Bearer {access}")));
                "user_oauth"
            }
        };
        let mut sent = Vec::new();
        for (name, value) in headers {
            let name = axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
            let mut value = HeaderValue::from_str(&value).map_err(|_| ())?;
            value.set_sensitive(true);
            sent.push((name, value));
        }
        Ok(Conn {
            key: person.name.clone(),
            headers: sent,
            auth: Some(kind),
        })
    }

    /// A one-use link, good for ten minutes, where `person` connects their own account to `server`.
    pub(super) async fn connect_link(
        &self,
        server: &Upstream,
        person: &Principal,
        origin: &str,
    ) -> Result<String, String> {
        let id = id::random_hex(16);
        self.keep
            .put(
                "connect",
                &id,
                json!({"server": server.name, "person": person.name, "team": person.team, "origin": origin, "exp": now() + PENDING_FOR}),
            )
            .await?;
        Ok(format!("{origin}/oauth/connect/{id}"))
    }

    /// The refusal of a call whose person has not connected their account to the server, with the link to do it.
    pub(super) async fn need(
        &self,
        asked: &mut Asked,
        server: &Upstream,
        why: Option<String>,
    ) -> Refusal {
        if let Some(why) = why {
            return Refusal::new(
                StatusCode::FORBIDDEN,
                "credential_needed",
                format!("Refused: {why}"),
            );
        }
        let person = asked.person.clone().unwrap_or_default();
        match self.connect_link(server, &person, &asked.origin).await {
            Ok(url) => {
                asked.connect = Some(url.clone());
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "credential_needed",
                    format!(
                        "Refused: MCP server \"{}\" runs each call with your own account, and \"{}\" has not connected one yet. Open {url} to connect it (the link works once, for ten minutes), then try again.",
                        server.name, person.name
                    ),
                )
            }
            Err(err) => Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                format!(
                    "Refused: MCP server \"{}\" needs your own account, and Gantry could not make a link to connect it: {err}. Try again, and tell your Gantry admin if it keeps failing.",
                    server.name
                ),
            ),
        }
    }

    async fn keep_credential(
        &self,
        server: &str,
        person: &str,
        team: &str,
        kind: &str,
        value: &Value,
    ) -> Result<(), String> {
        let sealed = self
            .keep
            .seal(&sealed_name(server, person), value.to_string().as_bytes())?;
        self.keep
            .put(
                "cred",
                &format!("{server}/{person}"),
                json!({"sealed": sealed, "kind": kind, "person": person, "team": team, "server": server, "at": gantry_core::audit::timestamp()}),
            )
            .await?;
        event(
            self,
            "mcp_credential",
            json!({"action": "connected", "person": person, "team": team, "server": server, "kind": kind}),
        )
        .await;
        Ok(())
    }

    /// One HTTP exchange with an authorization server, within the provider timeout. Returns the status and the
    /// JSON body (null when it is not JSON).
    async fn http(
        &self,
        request: axum::http::Request<Body>,
    ) -> Result<(StatusCode, Value), String> {
        let exchange = async {
            let response = self
                .app
                .client
                .request(request)
                .await
                .map_err(|_| "it could not be reached".to_string())?;
            let status = response.status();
            let bytes = axum::body::to_bytes(Body::new(response.into_body()), MAX_JSON)
                .await
                .map_err(|_| "its answer could not be read".to_string())?;
            Ok((
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            ))
        };
        tokio::time::timeout(self.app.timeouts.first_byte, exchange)
            .await
            .unwrap_or_else(|_| Err("it did not answer in time".into()))
    }

    async fn get_json(&self, url: &str) -> Option<Value> {
        let request = axum::http::Request::get(url)
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .ok()?;
        match self.http(request).await {
            Ok((status, body)) if status.is_success() && body.is_object() => Some(body),
            _ => None,
        }
    }

    async fn post_form(&self, url: &str, pairs: &[(&str, &str)]) -> Result<Value, String> {
        let body = with_query("", pairs).trim_start_matches('?').to_string();
        let request = axum::http::Request::post(url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(body))
            .map_err(|err| err.to_string())?;
        let (status, answer) = self.http(request).await?;
        if !status.is_success() {
            return Err(format!(
                "it answered with status {status}: {}",
                answer["error_description"]
                    .as_str()
                    .or(answer["error"].as_str())
                    .unwrap_or("no reason given")
            ));
        }
        Ok(answer)
    }

    /// The server's authorization server metadata: from its protected resource metadata (RFC 9728), then the
    /// authorization server's own (RFC 8414, or OpenID Connect discovery). Every endpoint must be https, or http to
    /// this machine.
    async fn discover(&self, server: &Upstream) -> Result<Value, String> {
        let split = |url: &str| -> Option<(String, String)> {
            let uri = url.parse::<Uri>().ok()?;
            let base = format!("{}://{}", uri.scheme_str()?, uri.authority()?);
            Some((base, uri.path().trim_end_matches('/').to_string()))
        };
        let (base, path) = split(&server.url).ok_or("its url cannot be read")?;
        let mut found = None;
        for url in [
            format!("{base}/.well-known/oauth-protected-resource{path}"),
            format!("{base}/.well-known/oauth-protected-resource"),
        ] {
            if let Some(body) = self.get_json(&url).await {
                found = Some(body);
                break;
            }
        }
        let issuer = found
            .as_ref()
            .and_then(|m| m["authorization_servers"][0].as_str())
            .map_or(base.clone(), str::to_string);
        let (ibase, ipath) = split(&issuer).ok_or("its authorization server url cannot be read")?;
        for url in [
            format!("{ibase}/.well-known/oauth-authorization-server{ipath}"),
            format!("{ibase}/.well-known/openid-configuration{ipath}"),
            format!("{issuer}/.well-known/openid-configuration"),
        ] {
            let Some(meta) = self.get_json(&url).await else {
                continue;
            };
            let endpoints = ["authorization_endpoint", "token_endpoint"];
            if endpoints.iter().all(|e| {
                meta[*e]
                    .as_str()
                    .is_some_and(gantry_core::config::secure_url)
            }) {
                return Ok(meta);
            }
        }
        Err(format!(
            "no OAuth authorization server metadata was found for it (asked {issuer}). Check that the server supports OAuth, or set oauth_client_id and give each person a header with user_auth: headers instead"
        ))
    }

    /// The client ID (and secret) Gantry uses at a server's authorization server: the one in the policy, or one it
    /// registered there itself, kept per server and redirect URI.
    async fn upstream_client(
        &self,
        server: &Upstream,
        meta: &Value,
        redirect: &str,
    ) -> Result<(String, Option<String>), String> {
        if let Some(UserAuth::OAuth {
            client_id: Some(id),
            ..
        }) = &server.user_auth
        {
            return Ok((id.clone(), server.client_secret.clone()));
        }
        if let Ok(Some(client)) = self.keep.get("upstream_client", &server.name).await
            && client["redirect_uri"] == redirect
            && let Some(id) = client["client_id"].as_str()
        {
            return Ok((id.to_string(), None));
        }
        let endpoint = meta["registration_endpoint"]
            .as_str()
            .filter(|u| gantry_core::config::secure_url(u))
            .ok_or("its authorization server offers no dynamic client registration. Register Gantry there by hand and set oauth_client_id (and oauth_client_secret_env) on the server")?;
        let body = json!({
            "client_name": "Gantry",
            "redirect_uris": [redirect],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        });
        let request = axum::http::Request::post(endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .map_err(|err| err.to_string())?;
        let (status, answer) = self.http(request).await?;
        let id = answer["client_id"]
            .as_str()
            .filter(|_| status.is_success())
            .ok_or_else(|| {
                format!("its authorization server refused to register Gantry (status {status})")
            })?;
        self.keep
            .put(
                "upstream_client",
                &server.name,
                json!({"client_id": id, "redirect_uri": redirect}),
            )
            .await?;
        Ok((id.to_string(), None))
    }

    /// A new access token for an OAuth credential whose token has run out, kept in its place. `None` when there is
    /// no refresh token or the authorization server refused it: the person connects again.
    async fn refresh(&self, server: &Upstream, person: &Principal, held: &Value) -> Option<Value> {
        let refresh = held["refresh_token"].as_str()?;
        let endpoint = held["token_endpoint"].as_str()?;
        let client_id = held["client_id"].as_str()?;
        let mut pairs = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
            ("resource", server.url.as_str()),
        ];
        if let Some(secret) = &server.client_secret {
            pairs.push(("client_secret", secret));
        }
        let answer = match self.post_form(endpoint, &pairs).await {
            Ok(answer) => answer,
            Err(err) => {
                eprintln!(
                    "gantry: the OAuth token of \"{}\" for MCP server \"{}\" could not be refreshed: {err}",
                    person.name, server.name
                );
                return None;
            }
        };
        let fresh = token_value(&answer, endpoint, client_id, Some(refresh))?;
        self.keep_credential(
            &server.name,
            &person.name,
            &person.team,
            "user_oauth",
            &fresh,
        )
        .await
        .ok()?;
        Some(fresh)
    }
}

/// What a credential is sealed under: its server and person, so a sealed value moved to another row does not open.
fn sealed_name(server: &str, person: &str) -> String {
    format!("mcp-credential:{server}:{person}")
}

/// The credential Gantry keeps from a token endpoint's answer.
fn token_value(
    answer: &Value,
    endpoint: &str,
    client_id: &str,
    old_refresh: Option<&str>,
) -> Option<Value> {
    let access = answer["access_token"].as_str()?;
    let expires = answer["expires_in"].as_u64().map_or(0, |s| now() + s);
    Some(json!({
        "access_token": access,
        // A server that does not turn refresh tokens over keeps the old one valid.
        "refresh_token": answer["refresh_token"].as_str().or(old_refresh),
        "expires_at": expires,
        "token_endpoint": endpoint,
        "client_id": client_id,
    }))
}

/// The token endpoint: a code and its PKCE verifier, or a refresh token, for a new access token and refresh token.
async fn token(State(mcp): State<Shared>, body: String) -> Response {
    let form = Form::parse(&body);
    let (client_id, subject, resource, scope) = match form.get("grant_type") {
        "authorization_code" => {
            let Ok(Some(code)) = mcp.keep.take("code", form.get("code")).await else {
                return oauth_error(
                    "invalid_grant",
                    "The code is unknown, used or older than a minute. Sign in again.",
                );
            };
            if code["client_id"] != form.get("client_id")
                || code["redirect_uri"] != form.get("redirect_uri")
            {
                return oauth_error(
                    "invalid_grant",
                    "The code was issued to another client or redirect_uri.",
                );
            }
            if code["challenge"] != challenge(form.get("code_verifier")).as_str() {
                return oauth_error(
                    "invalid_grant",
                    "code_verifier does not match the code_challenge this sign-in started with.",
                );
            }
            let resource = code["resource"].as_str().unwrap_or_default().to_string();
            if !form.get("resource").is_empty()
                && !resource.is_empty()
                && form.get("resource") != resource
            {
                return oauth_error(
                    "invalid_target",
                    "resource is not the one the sign-in asked for.",
                );
            }
            (
                form.get("client_id").to_string(),
                code["subject"].clone(),
                resource,
                code["scope"].clone(),
            )
        }
        "refresh_token" => {
            let held = mcp
                .keep
                .take("refresh", &sha(form.get("refresh_token")))
                .await;
            let Ok(Some(held)) = held else {
                return oauth_error(
                    "invalid_grant",
                    "The refresh token is unknown, used or expired. Sign in again.",
                );
            };
            if held["client_id"] != form.get("client_id") {
                return oauth_error(
                    "invalid_grant",
                    "The refresh token was issued to another client.",
                );
            }
            (
                form.get("client_id").to_string(),
                held["subject"].clone(),
                held["resource"].as_str().unwrap_or_default().to_string(),
                held["scope"].clone(),
            )
        }
        _ => {
            return oauth_error(
                "unsupported_grant_type",
                "Gantry takes grant_type authorization_code or refresh_token.",
            );
        }
    };
    let access = format!("{ACCESS_PREFIX}{}", id::random_hex(32));
    let refresh = format!("{REFRESH_PREFIX}{}", id::random_hex(32));
    let held = |exp: u64| json!({"subject": subject, "client_id": client_id, "resource": resource, "scope": scope, "exp": exp});
    let kept = async {
        mcp.keep
            .put("token", &sha(&access), held(now() + ACCESS_FOR))
            .await?;
        mcp.keep
            .put("refresh", &sha(&refresh), held(now() + REFRESH_FOR))
            .await
    };
    if let Err(err) = kept.await {
        return json_answer(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "temporarily_unavailable", "error_description": format!("The token could not be kept: {err}. Try again.")}),
        );
    }
    json_answer(
        StatusCode::OK,
        &json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_FOR,
            "refresh_token": refresh,
            "scope": scope.as_str().filter(|s| !s.is_empty()).unwrap_or("mcp"),
        }),
    )
}

/// The page behind a connect link: a form for the person's header values, or off to the server's sign-in.
async fn connect(State(mcp): State<Shared>, Path(id): Path<String>) -> Response {
    let Ok(Some(link)) = mcp.keep.get("connect", &id).await else {
        return gone();
    };
    let text = |f: &str| link[f].as_str().unwrap_or_default().to_string();
    let Some(server) = mcp
        .servers()
        .iter()
        .find(|s| s.name == text("server"))
        .cloned()
    else {
        return gone();
    };
    match &server.user_auth {
        Some(UserAuth::Headers(names)) => {
            let fields: String = names
                .iter()
                .map(|name| {
                    html::field(&html::Field {
                        id: name,
                        name,
                        label: name,
                        value: "",
                        mono: true,
                        extra: r#" type="password" autocomplete="off" required"#,
                        hint: "",
                        error: "",
                    })
                })
                .collect();
            page(
                StatusCode::OK,
                "Connect your account",
                &format!(
                    r#"<p class="t-body">Connect MCP server {} for <b>{}</b>. What you enter is sealed and sent only to that server, with your calls.</p><form method="post" action="/oauth/connect/{}">{fields}{}</form>"#,
                    html::esc(&server.name),
                    html::esc(&text("person")),
                    html::esc(&id),
                    html::button("Connect", "primary", "submit", "")
                ),
            )
        }
        Some(UserAuth::OAuth { scopes, .. }) => {
            let redirect = format!("{}/oauth/callback", text("origin"));
            let started = async {
                let meta = mcp.discover(&server).await?;
                let (client_id, client_secret) =
                    mcp.upstream_client(&server, &meta, &redirect).await?;
                let verifier = id::random_hex(32);
                let token_endpoint = meta["token_endpoint"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let mut held = link.clone();
                held["verifier"] = verifier.clone().into();
                held["token_endpoint"] = token_endpoint.into();
                held["client_id"] = client_id.clone().into();
                held["client_secret"] = client_secret.into();
                held["redirect_uri"] = redirect.clone().into();
                mcp.keep.put("connect", &id, held).await?;
                let scope = scopes.join(" ");
                let mut pairs = vec![
                    ("response_type", "code"),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect.as_str()),
                    ("state", id.as_str()),
                    ("resource", server.url.as_str()),
                ];
                let code_challenge = challenge(&verifier);
                pairs.push(("code_challenge", &code_challenge));
                pairs.push(("code_challenge_method", "S256"));
                if !scope.is_empty() {
                    pairs.push(("scope", &scope));
                }
                Ok::<_, String>(with_query(
                    meta["authorization_endpoint"].as_str().unwrap_or_default(),
                    &pairs,
                ))
            };
            match started.await {
                Ok(url) => gantry_console::redirect(&url),
                Err(err) => notice(
                    StatusCode::BAD_GATEWAY,
                    "Sign-in at the server is unavailable",
                    &format!(
                        "Gantry could not start a sign-in at MCP server {}: {err}. Tell your Gantry admin.",
                        server.name
                    ),
                ),
            }
        }
        Some(UserAuth::Exchange { .. }) | None => gone(),
    }
}

fn gone() -> Response {
    notice(
        StatusCode::NOT_FOUND,
        "This link has ended",
        "It was used already, or it is older than ten minutes. Call the tool again for a new link.",
    )
}

/// The person's header values, sealed and kept.
async fn connect_headers(
    State(mcp): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !gantry_console::same_origin(&headers) {
        return gantry_console::foreign();
    }
    let Ok(Some(link)) = mcp.keep.take("connect", &id).await else {
        return gone();
    };
    let text = |f: &str| link[f].as_str().unwrap_or_default().to_string();
    let Some(server) = mcp
        .servers()
        .iter()
        .find(|s| s.name == text("server"))
        .cloned()
    else {
        return gone();
    };
    let Some(UserAuth::Headers(names)) = &server.user_auth else {
        return gone();
    };
    let form = Form::parse(&body);
    let mut values = serde_json::Map::new();
    for name in names {
        let value = form.get(name).trim();
        if value.is_empty() || HeaderValue::from_str(value).is_err() {
            return notice(
                StatusCode::BAD_REQUEST,
                "Nothing was kept",
                &format!(
                    "{name} is empty or holds a character a header cannot carry, such as a line break. Call the tool again for a new link and paste the value alone."
                ),
            );
        }
        values.insert(name.clone(), value.into());
    }
    match mcp
        .keep_credential(
            &server.name,
            &text("person"),
            &text("team"),
            "user_headers",
            &json!({ "headers": values }),
        )
        .await
    {
        Ok(()) => connected(&server.name),
        Err(err) => notice(
            StatusCode::SERVICE_UNAVAILABLE,
            "Nothing was kept",
            &format!("Gantry could not keep your credential: {err}. Try again with a new link."),
        ),
    }
}

fn connected(server: &str) -> Response {
    notice(
        StatusCode::OK,
        "Connected",
        &format!(
            "MCP server {server} now runs your calls with your own account. Go back to your MCP client and try again."
        ),
    )
}

/// Where an upstream authorization server sends the person back: the code is traded for their token, sealed.
async fn callback(State(mcp): State<Shared>, uri: Uri) -> Response {
    let query = Form::of(&uri);
    let Ok(Some(link)) = mcp.keep.take("connect", query.get("state")).await else {
        return gone();
    };
    let text = |f: &str| link[f].as_str().unwrap_or_default().to_string();
    let Some(server) = mcp
        .servers()
        .iter()
        .find(|s| s.name == text("server"))
        .cloned()
    else {
        return gone();
    };
    if !query.get("error").is_empty() {
        return notice(
            StatusCode::BAD_REQUEST,
            "The server did not let you sign in",
            &format!(
                "MCP server {} said: {} {}. Call the tool again to try once more.",
                server.name,
                query.get("error"),
                query.get("error_description")
            ),
        );
    }
    let endpoint = text("token_endpoint");
    let client_id = text("client_id");
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", query.get("code")),
        (
            "redirect_uri",
            link["redirect_uri"].as_str().unwrap_or_default(),
        ),
        ("client_id", client_id.as_str()),
        (
            "code_verifier",
            link["verifier"].as_str().unwrap_or_default(),
        ),
        ("resource", server.url.as_str()),
    ];
    if let Some(secret) = link["client_secret"].as_str() {
        pairs.push(("client_secret", secret));
    }
    let traded = async {
        let answer = mcp.post_form(&endpoint, &pairs).await?;
        let value = token_value(&answer, &endpoint, &client_id, None)
            .ok_or("its answer holds no access_token")?;
        mcp.keep_credential(
            &server.name,
            &text("person"),
            &text("team"),
            "user_oauth",
            &value,
        )
        .await
    };
    match traded.await {
        Ok(()) => connected(&server.name),
        Err(err) => notice(
            StatusCode::BAD_GATEWAY,
            "Sign-in did not finish",
            &format!(
                "Gantry could not trade the sign-in code at MCP server {}: {err}. Call the tool again to try once more.",
                server.name
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pkce_challenge_is_rfc_7636s() {
        // RFC 7636 appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_loopback_redirect_matches_on_any_port_and_others_exactly() {
        let registered = json!([
            "http://127.0.0.1:3000/callback",
            "https://claude.ai/api/mcp/auth_callback"
        ]);
        assert!(redirect_registered(
            &registered,
            "http://127.0.0.1:51234/callback"
        ));
        assert!(redirect_registered(
            &registered,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!redirect_registered(&registered, "https://claude.ai/other"));
        assert!(!redirect_registered(
            &registered,
            "http://127.0.0.1:3000/elsewhere"
        ));
        assert!(redirect_ok("http://localhost:8080/cb"));
        assert!(!redirect_ok("http://evil.example.com/cb"));
        assert!(!redirect_ok("https://x.example.com/cb#frag"));
    }
}
