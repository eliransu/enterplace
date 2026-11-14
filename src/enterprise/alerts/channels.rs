//! Where alerts go, and the message each channel takes: Slack and Microsoft Teams incoming webhooks, PagerDuty
//! Events API v2, email over SMTP, and a webhook signed the Standard Webhooks way. Every message names the rule, says
//! what happened, and lists the audit records behind it with a link to each in the console.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{Value, json};

use crate::enterprise::siem::sinks::{Out, Sinks, signature, url_ok};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Slack,
    Teams,
    PagerDuty,
    Email,
    Webhook,
}

pub const KINDS: [Kind; 5] = [
    Kind::Slack,
    Kind::Teams,
    Kind::PagerDuty,
    Kind::Email,
    Kind::Webhook,
];

pub const PAGERDUTY: &str = "https://events.pagerduty.com/v2/enqueue";

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Teams => "teams",
            Self::PagerDuty => "pagerduty",
            Self::Email => "email",
            Self::Webhook => "webhook",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Slack => "Slack (incoming webhook)",
            Self::Teams => "Microsoft Teams (workflow or incoming webhook)",
            Self::PagerDuty => "PagerDuty (Events API v2)",
            Self::Email => "Email (SMTP)",
            Self::Webhook => "Webhook (signed HTTPS POST)",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        KINDS.into_iter().find(|k| k.word() == word)
    }
}

/// A channel as the sender uses it, its secret in clear: the webhook URL for Slack and Teams (the URL is the
/// credential), the routing key for PagerDuty, the SMTP password, or the webhook's signing secret.
#[derive(Clone, Debug)]
pub struct Channel {
    pub id: i64,
    pub kind: Kind,
    pub name: String,
    /// The SMTP server URL, the webhook URL, or PagerDuty's events URL.
    pub url: String,
    pub secret: String,
    pub options: Value,
}

impl Channel {
    fn option(&self, name: &str) -> &str {
        self.options[name].as_str().unwrap_or_default().trim()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Warning,
}

impl Severity {
    pub fn word(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
        }
    }
}

/// One alert, as every channel shows it.
#[derive(Clone, Debug)]
pub struct Alert {
    pub id: i64,
    pub rule: String,
    pub kind: &'static str,
    pub severity: Severity,
    /// What it is about: a team, a person, a key and address, a provider.
    pub key: String,
    pub summary: String,
    pub time: String,
    /// The audit records behind it: `{replica, n, hash, id}` each.
    pub evidence: Vec<Value>,
    /// The console, as people reach it (GANTRY_CONSOLE_URL), or empty for links relative to it.
    pub console: String,
}

impl Alert {
    pub fn link(&self) -> String {
        format!("{}/console/alerts#alert-{}", self.console, self.id)
    }

    /// The console's audit page for one decision.
    pub fn record_link(&self, id: &str) -> String {
        format!("{}/console/audit?q={id}", self.console)
    }

    fn records_text(&self) -> String {
        self.evidence
            .iter()
            .map(|e| {
                format!(
                    "record {} of {} ({}) {}",
                    e["n"],
                    e["replica"].as_str().unwrap_or_default(),
                    e["id"].as_str().unwrap_or("no decision ID"),
                    e["id"]
                        .as_str()
                        .map(|id| self.record_link(id))
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The JSON body the webhook gets, and the custom details PagerDuty shows.
    pub fn json(&self) -> Value {
        json!({
            "type": "gantry.alert",
            "alert": self.id,
            "rule": self.rule,
            "kind": self.kind,
            "severity": self.severity.word(),
            "subject": self.key,
            "summary": self.summary,
            "time": self.time,
            "link": self.link(),
            "records": self.evidence,
        })
    }

    fn title(&self) -> String {
        format!("Gantry alert: {}", self.rule)
    }
}

/// The request an HTTP channel is sent. Email goes through [`smtp`].
pub fn request(channel: &Channel, alert: &Alert, now: u64) -> Out {
    match channel.kind {
        Kind::Slack => {
            let records: Vec<String> = alert
                .evidence
                .iter()
                .filter_map(|e| e["id"].as_str())
                .map(|id| format!("<{}|{id}>", alert.record_link(id)))
                .collect();
            let text = format!(
                "*{}* ({})\n{}\nRecords: {}\n<{}|Open in Gantry>",
                alert.title(),
                alert.severity.word(),
                alert.summary,
                if records.is_empty() {
                    "none".to_string()
                } else {
                    records.join(", ")
                },
                alert.link()
            );
            Out::post(
                channel.secret.clone(),
                "application/json",
                json!({ "text": text }).to_string().into_bytes(),
            )
        }
        Kind::Teams => {
            // An Adaptive Card in a message: what Teams workflows ("post to a channel when a webhook request is
            // received") and the older incoming webhooks both take.
            let facts: Vec<Value> = [
                ("Rule", alert.rule.clone()),
                ("Severity", alert.severity.word().to_string()),
                ("Subject", alert.key.clone()),
                ("Time", alert.time.clone()),
            ]
            .into_iter()
            .map(|(title, value)| json!({ "title": title, "value": value }))
            .collect();
            let records: Vec<Value> = alert
                .evidence
                .iter()
                .filter_map(|e| e["id"].as_str())
                .map(|id| {
                    json!({ "type": "TextBlock", "wrap": true, "text": format!("[{id}]({})", alert.record_link(id)) })
                })
                .collect();
            let mut body = vec![
                json!({ "type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": alert.title(), "wrap": true }),
                json!({ "type": "TextBlock", "text": alert.summary, "wrap": true }),
                json!({ "type": "FactSet", "facts": facts }),
            ];
            body.extend(records);
            let card = json!({
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                        "actions": [{ "type": "Action.OpenUrl", "title": "Open in Gantry", "url": alert.link() }],
                    },
                }],
            });
            Out::post(
                channel.secret.clone(),
                "application/json",
                card.to_string().into_bytes(),
            )
        }
        Kind::PagerDuty => {
            let event = json!({
                "routing_key": channel.secret,
                "event_action": "trigger",
                // Repeats of the same rule and subject group into one incident.
                "dedup_key": format!("gantry-{}-{}", alert.rule, alert.key),
                "payload": {
                    "summary": format!("{}: {}", alert.rule, alert.summary).chars().take(1024).collect::<String>(),
                    "source": "gantry",
                    "severity": alert.severity.word(),
                    "component": alert.kind,
                    "custom_details": alert.json(),
                },
                "links": [{ "href": alert.link(), "text": "Open in Gantry" }],
            });
            Out::post(
                if channel.url.is_empty() {
                    PAGERDUTY.into()
                } else {
                    channel.url.clone()
                },
                "application/json",
                event.to_string().into_bytes(),
            )
        }
        Kind::Webhook | Kind::Email => {
            let body = alert.json().to_string().into_bytes();
            let id = format!("alert_{}", alert.id);
            let (header, value) = standard_signature(&channel.secret, &id, now, &body);
            Out::post(channel.url.clone(), "application/json", body)
                .header("webhook-id", id)
                .header("webhook-timestamp", now.to_string())
                .header(header, value)
                // The same HMAC of the body alone as audit export webhooks carry, for receivers already checking it.
                .header(
                    "x-gantry-signature",
                    format!(
                        "sha256={}",
                        signature(&channel.secret, &alert.json().to_string().into_bytes())
                    ),
                )
        }
    }
}

/// Standard Webhooks: `v1,<base64 HMAC-SHA256 of "id.timestamp.body">` under the bytes of the `whsec_` secret.
pub fn standard_signature(
    secret: &str,
    id: &str,
    timestamp: u64,
    body: &[u8],
) -> (&'static str, String) {
    let key = secret
        .strip_prefix("whsec_")
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .unwrap_or_else(|| secret.as_bytes().to_vec());
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let mut signed = format!("{id}.{timestamp}.").into_bytes();
    signed.extend_from_slice(body);
    let tag = ring::hmac::sign(&key, &signed);
    (
        "webhook-signature",
        format!(
            "v1,{}",
            base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
        ),
    )
}

/// Whether a channel's URL may be used: https (Slack, Teams, PagerDuty, webhook); for email `smtps://` (TLS from the
/// start, port 465) or `smtp://` (STARTTLS, port 587), plain only to this machine.
pub fn url_allowed(kind: Kind, url: &str) -> bool {
    match kind {
        Kind::Email => smtp_target(url).is_ok(),
        _ => url_ok(url),
    }
}

/// Sends one alert. Blocking: run it off the async threads. The error names what failed and how to fix it.
pub fn deliver(sinks: &Arc<Sinks>, channel: &Channel, alert: &Alert) -> Result<(), String> {
    if channel.kind == Kind::Email {
        return smtp(channel, alert);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let out = request(channel, alert, now);
    let (status, body) = sinks.call(&out)?;
    if !(200..300).contains(&status) {
        return Err(match status {
            401 | 403 => format!(
                "HTTP {status}: the channel refused the credentials. Check the webhook URL or routing key."
            ),
            404 => format!(
                "HTTP {status}: the webhook URL is gone. Make a new one and save the channel again."
            ),
            _ => format!(
                "HTTP {status} from the channel: {}",
                body.chars().take(200).collect::<String>()
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------- email

#[derive(Debug, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    /// TLS from the first byte (smtps), else STARTTLS unless the server is this machine.
    implicit: bool,
}

fn smtp_target(url: &str) -> Result<Target, String> {
    let bad = || {
        format!(
            "\"{url}\" is not an SMTP server URL. Use smtps://host:465 or smtp://host:587 (STARTTLS)."
        )
    };
    let (implicit, rest) = match (url.strip_prefix("smtps://"), url.strip_prefix("smtp://")) {
        (Some(rest), _) => (true, rest),
        (_, Some(rest)) => (false, rest),
        _ => return Err(bad()),
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().map_err(|_| bad())?),
        None => (rest, if implicit { 465 } else { 587 }),
    };
    if host.is_empty() || host.contains(['/', '@', ' ']) {
        return Err(bad());
    }
    Ok(Target {
        host: host.to_string(),
        port,
        implicit,
    })
}

fn local(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// An SMTP conversation over any stream: reads replies, sends commands.
struct Session<S: Read + Write> {
    reader: BufReader<S>,
}

impl<S: Read + Write> Session<S> {
    fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    /// The reply's code and text, all its lines.
    fn reply(&mut self) -> Result<(u16, String), String> {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            let read = self
                .reader
                .read_line(&mut line)
                .map_err(|err| format!("the SMTP server stopped answering: {err}"))?;
            if read == 0 {
                return Err("the SMTP server closed the connection".into());
            }
            text.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                let code = line.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
                return Ok((code, text));
            }
        }
    }

    fn expect(&mut self, want: u16, what: &str) -> Result<String, String> {
        let (code, text) = self.reply()?;
        if code != want {
            return Err(format!(
                "the SMTP server refused {what}: {}",
                text.trim().replace("\r\n", " ")
            ));
        }
        Ok(text)
    }

    fn send(&mut self, line: &str, want: u16, what: &str) -> Result<String, String> {
        let stream = self.reader.get_mut();
        stream
            .write_all(format!("{line}\r\n").as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|err| format!("the SMTP server could not be written to: {err}"))?;
        self.expect(want, what)
    }

    fn into_inner(self) -> S {
        self.reader.into_inner()
    }
}

fn tls_client(
    host: &str,
    tcp: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| format!("TLS could not be set up: {err}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("\"{host}\" is not a host name TLS can check"))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|err| format!("TLS to {host} could not start: {err}"))?;
    Ok(rustls::StreamOwned::new(connection, tcp))
}

/// The message as sent: headers and a plain text body, lines ending in CRLF and dot-stuffed.
pub fn message(from: &str, to: &[String], alert: &Alert, date: &str) -> String {
    let body = format!(
        "{}\r\n\r\nRule: {}\r\nSeverity: {}\r\nSubject: {}\r\nTime: {}\r\n\r\nAudit records behind it:\r\n{}\r\n\r\nOpen in Gantry: {}\r\n",
        alert.summary,
        alert.rule,
        alert.severity.word(),
        alert.key,
        alert.time,
        alert.records_text().replace('\n', "\r\n"),
        alert.link()
    );
    let subject: String = format!("[{}] {}", alert.severity.word(), alert.title())
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let mut text = format!(
        "From: {from}\r\nTo: {}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <gantry-alert-{}-{}@gantry>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
        to.join(", "),
        alert.id,
        date.len()
    );
    for line in body.split("\r\n") {
        if line.starts_with('.') {
            text.push('.');
        }
        text.push_str(line);
        text.push_str("\r\n");
    }
    text
}

fn converse<S: Read + Write>(
    session: &mut Session<S>,
    channel: &Channel,
    to: &[String],
    alert: &Alert,
) -> Result<(), String> {
    let user = channel.option("username");
    if !user.is_empty() {
        let plain = base64::engine::general_purpose::STANDARD
            .encode(format!("\0{user}\0{}", channel.secret));
        session.send(
            &format!("AUTH PLAIN {plain}"),
            235,
            "the username and password",
        )?;
    }
    let from = channel.option("from");
    session.send(&format!("MAIL FROM:<{from}>"), 250, "the sender")?;
    for address in to {
        session.send(&format!("RCPT TO:<{address}>"), 250, "a recipient")?;
    }
    session.send("DATA", 354, "the message")?;
    let date = gantry_core::audit::timestamp();
    let text = message(from, to, alert, &date);
    session.send(&format!("{text}."), 250, "the message")?;
    let _ = session.send("QUIT", 221, "QUIT");
    Ok(())
}

/// Sends the alert by email: TLS from the start (smtps) or STARTTLS, which is required unless the server is this
/// machine; then AUTH PLAIN when a username is set.
pub fn smtp(channel: &Channel, alert: &Alert) -> Result<(), String> {
    let target = smtp_target(&channel.url)?;
    let to: Vec<String> = channel
        .option("to")
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect();
    let clean =
        |a: &str| !a.is_empty() && a.contains('@') && !a.contains(['<', '>', '\r', '\n', ' ']);
    if to.is_empty() || !to.iter().all(|a| clean(a)) || !clean(channel.option("from")) {
        return Err("The email channel needs a From address and at least one To address.".into());
    }
    let addr = format!("{}:{}", target.host, target.port);
    let tcp = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|err| format!("{addr} could not be resolved: {err}"))?
        .next()
        .ok_or(format!("{addr} has no address"))
        .and_then(|a| {
            TcpStream::connect_timeout(&a, Duration::from_secs(10))
                .map_err(|err| format!("{addr} could not be reached: {err}. Check the host, the port and that this replica can reach it."))
        })?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(20)));
    let helo = "EHLO gantry";
    if target.implicit {
        let mut session = Session::new(tls_client(&target.host, tcp)?);
        session.expect(220, "the connection")?;
        session.send(helo, 250, "EHLO")?;
        return converse(&mut session, channel, &to, alert);
    }
    let mut session = Session::new(tcp);
    session.expect(220, "the connection")?;
    let features = session.send(helo, 250, "EHLO")?;
    if features.to_ascii_uppercase().contains("STARTTLS") {
        session.send("STARTTLS", 220, "STARTTLS")?;
        let mut session = Session::new(tls_client(&target.host, session.into_inner())?);
        session.send(helo, 250, "EHLO")?;
        return converse(&mut session, channel, &to, alert);
    }
    if !local(&target.host) {
        return Err(format!(
            "{} offers no STARTTLS, and Gantry sends email in the clear only to this machine. Use smtps://{}:465 or a server with STARTTLS.",
            target.host, target.host
        ));
    }
    converse(&mut session, channel, &to, alert)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_urls() {
        assert_eq!(
            smtp_target("smtps://mail.example.com"),
            Ok(Target {
                host: "mail.example.com".into(),
                port: 465,
                implicit: true
            })
        );
        assert_eq!(
            smtp_target("smtp://mail.example.com:2525"),
            Ok(Target {
                host: "mail.example.com".into(),
                port: 2525,
                implicit: false
            })
        );
        assert!(smtp_target("https://mail.example.com").is_err());
        assert!(smtp_target("smtp://user@mail.example.com").is_err());
    }

    #[test]
    fn standard_webhooks_signature_matches_the_spec_example() {
        // The example in the Standard Webhooks specification.
        let (_, value) = standard_signature(
            "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1614265330,
            br#"{"test": 2432232314}"#,
        );
        assert_eq!(value, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
    }
}
