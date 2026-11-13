//! The command line's side of `gantry login`, `gantry logout` and `gantry kill`: it calls a running Gantry over
//! HTTP. It lives here because the console already has the TLS client and the PKCE helpers it needs.

use std::time::Duration;

use axum::{
    body::Bytes,
    http::{Request, header},
};
use gantry_core::config::secure_url;
use http_body_util::Full;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Form, html::enc, sso};

/// How long `gantry login` waits for the person to finish signing in.
const WAIT: Duration = Duration::from_secs(5 * 60);

/// A key `gantry login` got.
#[derive(Debug)]
pub struct LoggedIn {
    pub key: String,
    pub name: String,
    pub team: String,
    pub expires: String,
}

/// The gateway's address without a trailing slash, refused unless a key may be sent to it.
pub fn gateway(url: &str) -> Result<String, String> {
    let url = url.trim().trim_end_matches('/');
    if !secure_url(url) {
        return Err(format!(
            "{url} is not an address a key may be sent to. Give the https address of Gantry, for example https://gantry.example.com (plain http only for 127.0.0.1 or localhost)."
        ));
    }
    Ok(url.to_string())
}

/// Calls the gateway with `key` and an optional JSON body. Returns the status and the JSON answer.
pub async fn call(
    method: &str,
    url: &str,
    key: &str,
    body: Option<&Value>,
) -> Result<(u16, Value), String> {
    let request = Request::builder()
        .method(method)
        .uri(url)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            body.map(Value::to_string).unwrap_or_default(),
        )))
        .map_err(|err| format!("{url} is not a URL Gantry can call: {err}"))?;
    sso::fetch(&sso::client(), request, "Gantry").await
}

fn random_url_safe() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| format!("the system gave no randomness ({err}). Try again."))?;
    Ok(sso::b64url(&bytes))
}

/// Signs in through the console's single sign-on and gets a personal key. `open` is given the address the person
/// must open in a browser. The browser comes back to a listener on 127.0.0.1 with a one-use code, which is traded
/// for the key with the PKCE verifier only this process holds.
pub async fn login(gateway: &str, open: impl FnOnce(&str)) -> Result<LoggedIn, String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|err| {
            format!("could not listen on 127.0.0.1 for the browser to come back: {err}")
        })?;
    let port = listener
        .local_addr()
        .map_err(|err| format!("could not listen on 127.0.0.1: {err}"))?
        .port();
    let (state, verifier) = (random_url_safe()?, random_url_safe()?);
    let challenge =
        sso::b64url(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    open(&format!(
        "{gateway}/console/cli/login?cli_port={port}&cli_state={state}&cli_challenge={challenge}"
    ));
    let query = tokio::time::timeout(WAIT, back(&listener, &state, gateway))
        .await
        .map_err(|_| {
            "no sign-in came back within 5 minutes. Run gantry login again.".to_string()
        })??;
    if !query.get("error").is_empty() {
        return Err(format!(
            "the sign-in was refused ({}): {}",
            query.get("error"),
            query.get("message")
        ));
    }
    let request = Request::post(format!("{gateway}/console/cli/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(format!(
            "code={}&verifier={}",
            enc(query.get("code")),
            enc(&verifier)
        ))))
        .map_err(|err| format!("{gateway} is not a URL Gantry can call: {err}"))?;
    let (status, answer) = sso::fetch(&sso::client(), request, "Gantry").await?;
    let text = |name: &str| answer[name].as_str().unwrap_or_default().to_string();
    if status != 200 || text("key").is_empty() {
        return Err(answer["error"]["message"]
            .as_str()
            .map_or_else(|| format!("Gantry answered HTTP {status}."), str::to_string));
    }
    Ok(LoggedIn {
        key: text("key"),
        name: text("name"),
        team: text("team"),
        expires: text("expires"),
    })
}

/// Waits for the browser's request with this state. Anything else that connects gets a 400 and is ignored. The
/// browser is sent on to the gateway's page for the end of a `gantry login`, styled as the console is.
async fn back(
    listener: &tokio::net::TcpListener,
    state: &str,
    gateway: &str,
) -> Result<Form, String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|err| format!("the listener on 127.0.0.1 failed: {err}"))?;
        let mut buffer = vec![0u8; 8192];
        let mut read = 0;
        while read < buffer.len() && !buffer[..read].windows(4).any(|w| w == b"\r\n\r\n") {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer[read..]))
                .await
            {
                Ok(Ok(n)) if n > 0 => read += n,
                _ => break,
            }
        }
        let head = String::from_utf8_lossy(&buffer[..read]);
        let target = head
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("GET "))
            .and_then(|rest| rest.split(' ').next())
            .unwrap_or("");
        let query = target
            .strip_prefix("/callback?")
            .map(Form::parse)
            .filter(|q| q.get("state") == state);
        let answer = match &query {
            Some(q) => format!(
                "HTTP/1.1 303 See Other\r\nLocation: {gateway}/console/cli/done?ok={}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                u8::from(q.get("error").is_empty())
            ),
            None => {
                let text = "This is not the sign-in gantry login is waiting for.";
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                )
            }
        };
        let _ = stream.write_all(answer.as_bytes()).await;
        if let Some(query) = query {
            return Ok(query);
        }
    }
}
