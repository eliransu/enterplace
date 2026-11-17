//! Upstream servers that are not Streamable HTTP: the older HTTP+SSE transport (MCP 2024-11-05) and stdio.
//!
//! Both are one connection that stays open: Enterplace writes a message (a POST to the endpoint the server named on its
//! event stream, or a line on the process's standard input) and the answer comes back later on what Enterplace reads
//! (the event stream, or the process's standard output), matched by its JSON-RPC id.
//!
//! A stdio server is a program the gateway starts. It starts only a command its own environment lists in
//! `ENTERPLACE_MCP_STDIO_ALLOW`, with an environment emptied of everything but what the policy's `env:` names, and it
//! is killed when its server leaves the policy or the gateway stops.
// ponytail: a request the server sends on these transports (sampling, elicitation) is refused, and its progress
// notifications are dropped: only Streamable HTTP relays them to the caller. Relay them when a legacy server needs it.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, StatusCode, header},
};
use enterplace_core::mcp::Transport;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use super::{Conn, Failure, Mcp, Server, failure, lock};
use crate::MAX_BODY_BYTES;

enum Writer {
    /// POST each message here, with these headers.
    Post(
        String,
        Vec<(HeaderName, HeaderValue)>,
        Box<crate::HttpClient>,
    ),
    Stdin(tokio::sync::Mutex<tokio::process::ChildStdin>),
}

pub(super) struct Duplex {
    waiting: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Value>>>,
    writer: Writer,
    closed: AtomicBool,
    /// What reads the answers. It owns the event stream or the process, so ending it closes or kills them.
    reader: Mutex<Option<tokio::task::AbortHandle>>,
}

impl Drop for Duplex {
    fn drop(&mut self) {
        if let Some(reader) = lock(&self.reader).take() {
            reader.abort();
        }
    }
}

impl Duplex {
    /// One message the server sent: the answer to a waiting request, or a request of its own, which is refused.
    async fn heard(&self, message: Value) {
        if let Some(id) = message["id"].as_u64()
            && message.get("method").is_none()
        {
            if let Some(tell) = lock(&self.waiting).remove(&id) {
                let _ = tell.send(message);
            }
            return;
        }
        if let (Some(method), Some(id)) = (message["method"].as_str(), message.get("id")) {
            let reply = if method == "ping" {
                json!({"jsonrpc": "2.0", "id": id, "result": {}})
            } else {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("Enterplace passes {method} to its caller only from a Streamable HTTP server.")}})
            };
            let _ = self.write(&reply).await;
        }
    }

    async fn write(&self, message: &Value) -> Result<(), Failure> {
        match &self.writer {
            Writer::Stdin(stdin) => {
                let mut stdin = stdin.lock().await;
                let line = format!("{message}\n");
                let written = async {
                    stdin.write_all(line.as_bytes()).await?;
                    stdin.flush().await
                };
                written
                    .await
                    .map_err(|_| failure("unreachable", "its process no longer reads its input"))
            }
            Writer::Post(url, headers, client) => {
                let mut request =
                    axum::http::Request::post(url).header(header::CONTENT_TYPE, "application/json");
                for (name, value) in headers {
                    request = request.header(name, value);
                }
                let request = request
                    .body(Body::from(message.to_string()))
                    .map_err(|err| {
                        failure(
                            "unreachable",
                            format!("the request could not be built: {err}"),
                        )
                    })?;
                let response = client
                    .request(request)
                    .await
                    .map_err(|_| failure("unreachable", "it could not be reached"))?;
                let status = response.status();
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Err(failure(
                        "unauthorized",
                        format!("it refused the credential Enterplace sent (status {status})"),
                    ));
                }
                if !status.is_success() {
                    return Err(failure(
                        "http_error",
                        format!("it answered with status {status}"),
                    ));
                }
                Ok(())
            }
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // Whoever waits learns at once that no answer is coming.
        lock(&self.waiting).clear();
    }
}

/// The first whole event of an event stream read so far: its name, its data, and how many bytes it took.
fn raw_event(read: &[u8]) -> Option<(String, String, usize)> {
    let text = String::from_utf8_lossy(read);
    let (end, sep) = [("\r\n\r\n", 4), ("\n\n", 2)]
        .into_iter()
        .filter_map(|(mark, len)| text.find(mark).map(|at| (at, len)))
        .min()?;
    let mut name = String::from("message");
    let mut data = Vec::new();
    for line in text[..end].lines() {
        if let Some(value) = line.strip_prefix("event:") {
            name = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    Some((name, data.join("\n"), text[..end].len() + sep))
}

/// Where a legacy server takes messages: the URI its `endpoint` event names, which must be on the server's own
/// origin, so a server cannot point Enterplace (and the credential it sends) somewhere else.
fn endpoint(server_url: &str, named: &str) -> Option<String> {
    let origin_end = server_url.find("://").map(|at| {
        server_url[at + 3..]
            .find('/')
            .map_or(server_url.len(), |slash| at + 3 + slash)
    })?;
    let origin = &server_url[..origin_end];
    if named.starts_with('/') && !named.starts_with("//") {
        return Some(format!("{origin}{named}"));
    }
    (named.starts_with(&format!("{origin}/")) || named == origin).then(|| named.to_string())
}

impl Mcp {
    /// Sends one message on the server's open connection for `conn`, opening it at `initialize`, and returns the
    /// answer to a request (null for a notification or an answer of Enterplace's own).
    pub(super) async fn send_duplex(
        &self,
        server: &Server,
        in_session: bool,
        conn: &Conn,
        body: &Value,
    ) -> Result<Value, Failure> {
        let open = {
            let mut held = server.duplex.lock().await;
            held.retain(|_, d| !d.closed.load(Ordering::Relaxed));
            match held.get(&conn.key) {
                Some(open) => open.clone(),
                // The connection a session lived on is gone: the session ended with it.
                None if in_session => {
                    return Err(failure("session_ended", "its connection closed"));
                }
                None => {
                    let opened = tokio::time::timeout(
                        self.app.timeouts.first_byte,
                        self.open_duplex(server, conn),
                    )
                    .await
                    .unwrap_or_else(|_| Err(failure("timeout", "it did not answer in time")))?;
                    held.insert(conn.key.clone(), opened.clone());
                    opened
                }
            }
        };
        let Some(id) = body["id"].as_u64().filter(|_| body.get("method").is_some()) else {
            open.write(body).await?;
            return Ok(Value::Null);
        };
        let (tell, answer) = tokio::sync::oneshot::channel();
        lock(&open.waiting).insert(id, tell);
        let exchange = async {
            open.write(body).await?;
            answer
                .await
                .map_err(|_| failure("unreachable", "its connection closed before it answered"))
        };
        let answer = tokio::time::timeout(self.app.timeouts.first_byte, exchange)
            .await
            .unwrap_or_else(|_| Err(failure("timeout", "it did not answer in time")));
        lock(&open.waiting).remove(&id);
        answer
    }

    async fn open_duplex(&self, server: &Server, conn: &Conn) -> Result<Arc<Duplex>, Failure> {
        if let Transport::Stdio { command, args, .. } = &server.transport {
            let mut child = tokio::process::Command::new(command)
                .args(args)
                // Nothing of the gateway's own environment (its provider keys, its master key) reaches the process.
                .env_clear()
                .envs(
                    server
                        .stdio_env
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str())),
                )
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|err| {
                    failure(
                        "unreachable",
                        format!("{command} could not be started: {err}"),
                    )
                })?;
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                return Err(failure(
                    "unreachable",
                    "its process gave no input or output to speak on",
                ));
            };
            let open = Arc::new(Duplex {
                waiting: Mutex::default(),
                writer: Writer::Stdin(tokio::sync::Mutex::new(stdin)),
                closed: AtomicBool::new(false),
                reader: Mutex::new(None),
            });
            let weak = Arc::downgrade(&open);
            let task = tokio::spawn(async move {
                // Held here, so the process is killed when this task ends or is ended.
                let _child = child;
                let mut lines = tokio::io::BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.len() > MAX_BODY_BYTES {
                        break;
                    }
                    let Ok(message) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if !pass(&weak, message).await {
                        return;
                    }
                }
                if let Some(open) = weak.upgrade() {
                    open.close();
                }
            });
            *lock(&open.reader) = Some(task.abort_handle());
            return Ok(open);
        }
        let headers: Vec<(HeaderName, HeaderValue)> = server
            .headers
            .iter()
            .chain(&conn.headers)
            .cloned()
            .collect();
        let mut request =
            axum::http::Request::get(&server.url).header(header::ACCEPT, "text/event-stream");
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        let request = request.body(Body::empty()).map_err(|err| {
            failure(
                "unreachable",
                format!("the request could not be built: {err}"),
            )
        })?;
        let response = self
            .app
            .client
            .request(request)
            .await
            .map_err(|_| failure("unreachable", "it could not be reached"))?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(failure(
                "unauthorized",
                format!("it refused the credential Enterplace sent (status {status})"),
            ));
        }
        if !status.is_success() {
            return Err(failure(
                "http_error",
                format!(
                    "it answered with status {status}; a server set to transport: sse opens an event stream on GET"
                ),
            ));
        }
        let mut body = Body::new(response.into_body());
        let mut read: Vec<u8> = Vec::new();
        // The first event names where messages go.
        let post_to = loop {
            if let Some((name, data, used)) = raw_event(&read) {
                read.drain(..used);
                if name == "endpoint" {
                    break endpoint(&server.url, data.trim()).ok_or_else(|| {
                        failure(
                            "unreadable_answer",
                            "its endpoint event names an address on another origin, which Enterplace does not send to",
                        )
                    })?;
                }
                continue;
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if read.len() + data.len() > MAX_BODY_BYTES {
                            return Err(failure(
                                "unreadable_answer",
                                "its stream sent no endpoint event",
                            ));
                        }
                        read.extend_from_slice(&data);
                    }
                }
                _ => {
                    return Err(failure(
                        "unreadable_answer",
                        "its stream ended before it named the endpoint to post to",
                    ));
                }
            }
        };
        let open = Arc::new(Duplex {
            waiting: Mutex::default(),
            writer: Writer::Post(post_to, headers, Box::new(self.app.client.clone())),
            closed: AtomicBool::new(false),
            reader: Mutex::new(None),
        });
        let weak = Arc::downgrade(&open);
        let task = tokio::spawn(async move {
            loop {
                while let Some((_, data, used)) = raw_event(&read) {
                    read.drain(..used);
                    if let Ok(message) = serde_json::from_str::<Value>(&data)
                        && !pass(&weak, message).await
                    {
                        return;
                    }
                }
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if read.len() + data.len() > MAX_BODY_BYTES {
                                break;
                            }
                            read.extend_from_slice(&data);
                        }
                    }
                    _ => break,
                }
            }
            if let Some(open) = weak.upgrade() {
                open.close();
            }
        });
        *lock(&open.reader) = Some(task.abort_handle());
        Ok(open)
    }
}

/// Hands a message to its connection. `false` once the connection is gone.
async fn pass(open: &Weak<Duplex>, message: Value) -> bool {
    let Some(open) = open.upgrade() else {
        return false;
    };
    open.heard(message).await;
    true
}

#[cfg(test)]
mod tests {
    use super::{endpoint, raw_event};

    #[test]
    fn an_endpoint_event_is_read_and_kept_to_the_servers_origin() {
        let stream = b"event: endpoint\ndata: /messages?session=1\n\nevent: message\ndata: {}\n\n";
        let Some((name, data, used)) = raw_event(stream) else {
            panic!("the first event is whole");
        };
        assert_eq!(
            (name.as_str(), data.as_str()),
            ("endpoint", "/messages?session=1")
        );
        assert!(raw_event(&stream[used..]).is_some_and(|(name, ..)| name == "message"));
        let url = "https://mcp.example.com/sse";
        assert_eq!(
            endpoint(url, "/messages?session=1").as_deref(),
            Some("https://mcp.example.com/messages?session=1")
        );
        assert_eq!(
            endpoint(url, "https://mcp.example.com/m").as_deref(),
            Some("https://mcp.example.com/m")
        );
        assert_eq!(endpoint(url, "https://evil.example.com/m"), None);
        assert_eq!(endpoint(url, "//evil.example.com/m"), None);
        assert_eq!(endpoint(url, "https://mcp.example.com.evil.com/m"), None);
    }
}
