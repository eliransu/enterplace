//! Alerting against a real Postgres and local mock receivers: every channel's message, the rules on spend, limits,
//! providers and security events, deduplication and the hourly cap, the alert record in the chain with the records
//! behind it, audit records for every change, and the license gate.

use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use gantry_core::audit;
use serde_json::{Map, Value, json};

use super::channels::{self, Alert, Channel, Kind as ChannelKind, Severity};
use super::*;
use crate::enterprise::siem::tests::{Sink, chain_lines, quiet};
use crate::enterprise::testing::*;

fn alert() -> Alert {
    Alert {
        id: 7,
        rule: "Payments budget".into(),
        kind: "budget",
        severity: Severity::Warning,
        key: "team:payments:2026-11".into(),
        summary: "team:payments has spent $81.00 in 2026-11, reaching $80.00.".into(),
        time: "2026-11-14T10:00:00.000Z".into(),
        evidence: vec![json!({ "replica": "pod-0-abc", "n": 12, "hash": "h12", "id": "01DEC" })],
        console: "https://gantry.example.com".into(),
    }
}

fn channel(kind: ChannelKind, url: &str, secret: &str, options: Value) -> Channel {
    Channel {
        id: 1,
        kind,
        name: "test".into(),
        url: url.into(),
        secret: secret.into(),
        options,
    }
}

#[test]
fn each_channel_gets_its_documented_message_with_the_records_behind_the_alert() -> Result<(), Error>
{
    let a = alert();
    let json_of = |out: &crate::enterprise::siem::sinks::Out| -> Value {
        serde_json::from_slice(&out.body).unwrap_or(Value::Null)
    };

    let slack = channels::request(
        &channel(
            ChannelKind::Slack,
            "",
            "https://hooks.slack.com/services/T/B/X",
            json!({}),
        ),
        &a,
        1,
    );
    assert_eq!(
        slack.url, "https://hooks.slack.com/services/T/B/X",
        "the secret is the URL"
    );
    let text = json_of(&slack)["text"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(text.contains("Payments budget") && text.contains("$81.00"));
    assert!(
        text.contains("https://gantry.example.com/console/audit?q=01DEC"),
        "{text}"
    );
    assert!(text.contains("https://gantry.example.com/console/alerts#alert-7"));

    let teams = channels::request(
        &channel(
            ChannelKind::Teams,
            "",
            "https://example.webhook.office.com/x",
            json!({}),
        ),
        &a,
        1,
    );
    let card = json_of(&teams);
    assert_eq!(card["type"], "message");
    assert_eq!(
        card["attachments"][0]["contentType"],
        "application/vnd.microsoft.card.adaptive"
    );
    let content = &card["attachments"][0]["content"];
    assert_eq!(content["type"], "AdaptiveCard");
    assert_eq!(
        content["actions"][0]["url"],
        "https://gantry.example.com/console/alerts#alert-7"
    );
    assert!(content.to_string().contains("01DEC"));

    let pd = channels::request(
        &channel(ChannelKind::PagerDuty, "", "R0UTINGKEY", json!({})),
        &a,
        1,
    );
    assert_eq!(pd.url, channels::PAGERDUTY);
    let event = json_of(&pd);
    assert_eq!(event["routing_key"], "R0UTINGKEY");
    assert_eq!(event["event_action"], "trigger");
    assert_eq!(event["payload"]["severity"], "warning");
    assert_eq!(event["payload"]["source"], "gantry");
    assert_eq!(
        event["dedup_key"],
        "gantry-Payments budget-team:payments:2026-11"
    );
    assert_eq!(event["payload"]["custom_details"]["records"][0]["n"], 12);

    let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    let hook = channels::request(
        &channel(
            ChannelKind::Webhook,
            "https://example.com/hook",
            secret,
            json!({}),
        ),
        &a,
        1_700_000_000,
    );
    let header = |name: &str| {
        hook.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(header("webhook-id"), "alert_7");
    assert_eq!(header("webhook-timestamp"), "1700000000");
    let (_, expected) = channels::standard_signature(secret, "alert_7", 1_700_000_000, &hook.body);
    assert_eq!(header("webhook-signature"), expected);
    let (_, wrong) =
        channels::standard_signature("whsec_d3Jvbmc=", "alert_7", 1_700_000_000, &hook.body);
    assert_ne!(header("webhook-signature"), wrong);
    assert_eq!(json_of(&hook)["records"][0]["id"], "01DEC");
    Ok(())
}

/// An SMTP server on this machine that offers no STARTTLS (Gantry sends in the clear only to this machine) and keeps
/// what it was told.
/// What the SMTP server was told, line by line.
type Said = Arc<Mutex<Vec<String>>>;

fn smtp_server() -> Result<(u16, Said), Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let said = Arc::new(Mutex::new(Vec::new()));
    let keep = said.clone();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let Ok(mut out) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(stream);
        let mut reply = |text: &str| {
            let _ = out.write_all(format!("{text}\r\n").as_bytes());
        };
        reply("220 test ESMTP");
        let mut data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if let Ok(mut s) = keep.lock() {
                s.push(line.trim_end_matches("\r\n").to_string());
            }
            if data {
                if line == ".\r\n" {
                    data = false;
                    reply("250 queued");
                }
                continue;
            }
            let upper = line.to_ascii_uppercase();
            match () {
                _ if upper.starts_with("EHLO") => reply("250-test\r\n250 AUTH PLAIN"),
                _ if upper.starts_with("AUTH PLAIN") => reply("235 ok"),
                _ if upper.starts_with("MAIL") || upper.starts_with("RCPT") => reply("250 ok"),
                _ if upper.starts_with("DATA") => {
                    data = true;
                    reply("354 go");
                }
                _ if upper.starts_with("QUIT") => {
                    reply("221 bye");
                    return;
                }
                _ => reply("500 what"),
            }
        }
    });
    Ok((port, said))
}

#[test]
fn email_goes_over_smtp_with_auth_and_the_records_and_never_in_the_clear_to_another_host()
-> Result<(), Error> {
    let (port, said) = smtp_server()?;
    let mut a = alert();
    a.summary = ".a line that starts with a dot".into();
    let ch = channel(
        ChannelKind::Email,
        &format!("smtp://127.0.0.1:{port}"),
        "smtp-password",
        json!({ "username": "gantry", "from": "gantry@example.com", "to": "ops@example.com, sec@example.com" }),
    );
    channels::smtp(&ch, &a)?;
    let lines = said.lock().map(|s| s.clone()).unwrap_or_default();
    use base64::Engine;
    let plain = base64::engine::general_purpose::STANDARD.encode("\0gantry\0smtp-password");
    assert!(lines.contains(&format!("AUTH PLAIN {plain}")), "{lines:?}");
    assert!(lines.contains(&"MAIL FROM:<gantry@example.com>".to_string()));
    assert!(lines.contains(&"RCPT TO:<sec@example.com>".to_string()));
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("Subject: [warning] Gantry alert: Payments budget"))
    );
    assert!(
        lines.contains(&"..a line that starts with a dot".to_string()),
        "dot-stuffed"
    );
    assert!(lines.iter().any(|l| l.contains("/console/audit?q=01DEC")));

    // A server elsewhere that offers no STARTTLS is refused before anything is sent.
    assert!(channels::url_allowed(
        ChannelKind::Email,
        "smtps://smtp.example.com"
    ));
    assert!(!channels::url_allowed(
        ChannelKind::Email,
        "https://smtp.example.com"
    ));
    assert!(!channels::url_allowed(
        ChannelKind::Webhook,
        "http://example.com/hook"
    ));
    Ok(())
}

#[test]
fn working_hours_and_weekends() {
    let at = |text: &str| parse_time(text).unwrap_or(SystemTime::UNIX_EPOCH);
    let hours = parse_hours("08-19").unwrap_or((0, 24, 0));
    // 2026-11-16 is a Monday.
    assert!(!after_hours(at("2026-11-16T10:00:00.000Z"), hours));
    assert!(after_hours(at("2026-11-16T19:30:00.000Z"), hours));
    assert!(after_hours(at("2026-11-16T07:59:00.000Z"), hours));
    assert!(
        after_hours(at("2026-11-14T10:00:00.000Z"), hours),
        "Saturday"
    );
    let israel = parse_hours("08-19+0200").unwrap_or((0, 24, 0));
    assert!(
        !after_hours(at("2026-11-16T06:30:00.000Z"), israel),
        "08:30 local"
    );
    assert!(parse_hours("19-08").is_none() && parse_hours("08-19+2").is_none());
}

// ---------------------------------------------------------------- against Postgres

fn write(gw: &Gateway, fields: Value) -> Result<(), Error> {
    let mut record = Map::new();
    record.insert("time".into(), audit::timestamp().into());
    if let Value::Object(map) = fields {
        record.extend(map);
    }
    gw.log.append_record(&record)?;
    Ok(())
}

fn request(
    gw: &Gateway,
    id: &str,
    person: &str,
    key: &str,
    client: &str,
    code: Option<&str>,
) -> Result<(), Error> {
    let mut record = audit::record(&audit::Entry {
        id,
        person: Some(person),
        team: Some("payments"),
        client: Some(client),
        key: Some(key),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("m"),
        allowed: code.is_none(),
        code,
        provider: "openai",
        ..Default::default()
    });
    record.insert("team".into(), "payments".into());
    gw.log.append_record(&record)?;
    Ok(())
}

pub(crate) async fn rows(
    url: &str,
    sql: &str,
) -> Result<Vec<gantry_server::store::tokio_postgres::Row>, Error> {
    use gantry_server::store::tokio_postgres;
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    Ok(client.query(sql, &[]).await?)
}

async fn run(ex: &Arc<crate::enterprise::siem::Exporter>) -> Result<(), Error> {
    while ex.ingest().await? > 0 {}
    let engine = ex.alerts.get().ok_or("no alert engine")?;
    engine.evaluate().await?;
    Ok(())
}

#[tokio::test]
async fn rules_fire_once_with_their_records_and_every_change_is_recorded() -> Result<(), Error> {
    let Some(url) = database("alerts_flow").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("alerts_flow", &url, &["alerts"])?;
    let mut owner = Browser::admin(&gw.app).await?;

    let saved = owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "channel_save"),
                ("kind", "webhook"),
                ("name", "ops hook"),
                ("url", &format!("{}/in/alerts", sink.base)),
            ],
        )
        .await?;
    assert!(saved.text.contains("Saved channel 1"), "{}", saved.text);
    let secret = saved
        .text
        .split(r#"id="signing-secret">"#)
        .nth(1)
        .and_then(|r| r.split('<').next())
        .map(str::to_string)
        .filter(|r| r.starts_with("whsec_"))
        .ok_or("no signing secret")?;

    let hour = audit::timestamp()
        .get(11..13)
        .and_then(|h| h.parse::<u32>().ok())
        .unwrap_or(0);
    let closed = if hour < 22 {
        format!("{:02}-{:02}", hour + 1, hour + 2)
    } else {
        "00-01".into()
    };
    let rules: Vec<Vec<(&str, String)>> = vec![
        vec![
            ("kind", "guardrail_block".into()),
            ("name_rule", "Blocks".into()),
            ("count", "1".into()),
            ("by", "person".into()),
        ],
        vec![
            ("kind", "rate_limit".into()),
            ("name_rule", "Limits".into()),
            ("count", "2".into()),
            ("minutes", "10".into()),
        ],
        vec![
            ("kind", "budget".into()),
            ("name_rule", "Payments budget".into()),
            ("scope", "team".into()),
            ("name", "payments".into()),
            ("period", "month".into()),
            ("usd", "1".into()),
        ],
        vec![
            ("kind", "kill_switch".into()),
            ("name_rule", "Kills".into()),
        ],
        vec![
            ("kind", "new_ip".into()),
            ("name_rule", "New address".into()),
        ],
        vec![
            ("kind", "after_hours".into()),
            ("name_rule", "Night".into()),
            ("hours", closed),
        ],
        vec![
            ("kind", "unusual_spend".into()),
            ("name_rule", "Unusual".into()),
            ("usd", "1".into()),
        ],
        vec![
            ("kind", "provider_errors".into()),
            ("name_rule", "Provider down".into()),
        ],
        vec![
            ("kind", "latency".into()),
            ("name_rule", "Slow".into()),
            ("ms", "1".into()),
        ],
        vec![("kind", "system".into()), ("name_rule", "System".into())],
    ];
    for fields in &rules {
        let mut form: Vec<(&str, &str)> = vec![
            ("action", "rule_save"),
            ("channels", "1"),
            ("cooldown", "60"),
        ];
        form.extend(fields.iter().map(|(k, v)| (*k, v.as_str())));
        let answer = owner.go(&gw.app, "POST", "/console/alerts", &form).await?;
        assert!(answer.text.contains("Added rule"), "{}", answer.text);
    }
    let refused = owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "rule_save"),
                ("kind", "budget"),
                ("name_rule", "bad"),
                ("scope", "planet"),
            ],
        )
        .await?;
    assert!(refused.text.contains("Scope is all, team, person or key"));

    // Learn alice's first address, then everything that should set a rule off.
    request(&gw, "r-learn", "alice", "aaaa1111", "10.0.0.1", None)?;
    run(&ex).await?;
    let first = sink.deliveries();
    let first_rules: Vec<Value> = first.iter().map(|h| h.json()["rule"].clone()).collect();
    assert!(
        first_rules.contains(&json!("Night")),
        "a key used outside working hours: {first_rules:?}"
    );
    assert!(
        !first_rules.contains(&json!("New address")),
        "a key's first address is learned"
    );
    sink.clear();
    request(
        &gw,
        "r-block",
        "alice",
        "aaaa1111",
        "10.0.0.1",
        Some("guardrail_blocked"),
    )?;
    request(
        &gw,
        "r-lim1",
        "alice",
        "aaaa1111",
        "10.0.0.1",
        Some("rate_limited"),
    )?;
    request(
        &gw,
        "r-lim2",
        "alice",
        "aaaa1111",
        "10.0.0.1",
        Some("rate_limited"),
    )?;
    request(&gw, "r-new", "alice", "aaaa1111", "203.0.113.9", None)?;
    // Two seconds after its decision: slow.
    let later = audit::rfc3339(SystemTime::now() + Duration::from_secs(2));
    write(
        &gw,
        json!({ "event": "usage", "id": "r-new", "time": later, "person": "alice", "team": "payments", "key": "aaaa1111", "model": "m", "provider": "openai", "status": 503, "charged_usd": 2.5 }),
    )?;
    write(
        &gw,
        json!({ "event": "admin", "id": "k1", "person": "noa", "action": "set_kill", "verdict": "allow", "target": { "scope": "team", "value": "payments", "reason": "leak" } }),
    )?;
    run(&ex).await?;

    let hits = sink.deliveries();
    let fired: Vec<String> = hits
        .iter()
        .map(|h| h.json()["rule"].as_str().unwrap_or_default().to_string())
        .collect();
    for want in [
        "Blocks",
        "Limits",
        "Payments budget",
        "Kills",
        "New address",
        "Unusual",
        "Provider down",
        "Slow",
    ] {
        assert!(
            fired.iter().any(|f| f == want),
            "{want} did not fire: {fired:?}"
        );
    }
    assert!(
        !fired.iter().any(|f| f == "System"),
        "nothing was wrong with the log or store"
    );
    for hit in &hits {
        let id = hit.header("webhook-id").to_string();
        let ts: u64 = hit.header("webhook-timestamp").parse().unwrap_or(0);
        assert_eq!(
            hit.header("webhook-signature"),
            channels::standard_signature(&secret, &id, ts, &hit.body).1
        );
    }
    let block = hits
        .iter()
        .find(|h| h.json()["rule"] == "Blocks")
        .ok_or("no block alert")?
        .json();
    assert_eq!(
        block["records"][0]["id"], "r-block",
        "the alert names its record"
    );
    assert_eq!(block["subject"], "person:alice");
    let new_ip = hits
        .iter()
        .find(|h| h.json()["rule"] == "New address")
        .ok_or("no new address")?
        .json();
    assert!(
        new_ip["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("203.0.113.9")
    );

    // Each alert is in the chain, with the records behind it.
    let chain = chain_lines(&gw)?;
    let alert_records: Vec<Value> = chain
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "alert")
        .collect();
    assert_eq!(alert_records.len(), first.len() + hits.len());
    assert!(
        alert_records
            .iter()
            .any(|r| r["rule"] == "Blocks" && r["records"][0]["id"] == "r-block")
    );
    // Every rule change is an admin record, the refused one with its code.
    let saved_rules = chain
        .iter()
        .filter(|l| l.contains("\"action\":\"alert_rule_saved\""))
        .count();
    assert_eq!(saved_rules, rules.len() + 1);
    assert!(
        chain
            .iter()
            .any(|l| l.contains("\"action\":\"alert_rule_saved\"")
                && l.contains("\"code\":\"invalid_rule\""))
    );
    assert!(
        chain
            .iter()
            .any(|l| l.contains("\"action\":\"alert_channel_saved\""))
    );
    assert!(
        !chain.iter().any(|l| l.contains(&secret)),
        "the signing secret is never recorded"
    );

    // Again within the quiet period: counted, not sent.
    sink.clear();
    request(
        &gw,
        "r-block2",
        "alice",
        "aaaa1111",
        "10.0.0.1",
        Some("guardrail_blocked"),
    )?;
    write(
        &gw,
        json!({ "event": "usage", "id": "r-x", "person": "alice", "team": "payments", "key": "aaaa1111", "model": "m", "provider": "openai", "status": 200, "charged_usd": 0.5 }),
    )?;
    run(&ex).await?;
    assert!(
        sink.deliveries().is_empty(),
        "{:?}",
        sink.deliveries()
            .iter()
            .map(|h| h.json())
            .collect::<Vec<_>>()
    );
    let suppressed = rows(&url, "SELECT suppressed FROM enterprise_alert_state s JOIN enterprise_alert_rules r ON r.id = s.rule WHERE r.name = 'Blocks'").await?;
    assert_eq!(
        suppressed
            .first()
            .map(|r| r.try_get::<_, i64>(0))
            .transpose()?,
        Some(1)
    );

    // The page lists the alerts with links to their records.
    let page = owner.go(&gw.app, "GET", "/console/alerts", &[]).await?;
    assert!(
        page.text.contains("/console/audit?q=r-block"),
        "{}",
        page.text
    );
    assert!(page.text.contains("sent to ops hook"));

    // A rule turned off fires nothing.
    let off = owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[("action", "rule_disable"), ("id", "2")],
        )
        .await?;
    assert!(off.text.contains("Rule 2 is off"));
    assert!(
        owner
            .go(&gw.app, "GET", "/console/alerts", &[])
            .await?
            .text
            .contains(r#"id="rule-state-2">off<"#)
    );
    Ok(())
}

#[tokio::test]
async fn trouble_with_the_audit_log_or_store_alerts_the_system_rules() -> Result<(), Error> {
    let Some(url) = database("alerts_system").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("alerts_system", &url, &["alerts"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "channel_save"),
                ("kind", "webhook"),
                ("name", "hook"),
                ("url", &format!("{}/in/a", sink.base)),
            ],
        )
        .await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "rule_save"),
                ("kind", "system"),
                ("name_rule", "System"),
                ("channels", "1"),
                ("cooldown", "60"),
            ],
        )
        .await?;
    let engine = ex.alerts.get().ok_or("no engine")?.clone();
    engine
        .tick(Some(&"the audit log at /x cannot be read".to_string()))
        .await;
    engine
        .tick(Some(&"the audit log at /x cannot be read".to_string()))
        .await;
    let hits = sink.deliveries();
    assert_eq!(hits.len(), 1, "once per quiet period");
    assert_eq!(hits[0].json()["severity"], "critical");
    assert!(
        hits[0].json()["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot be read into Postgres")
    );

    // A refusal for the store going away sets it off too.
    request(
        &gw,
        "r-store",
        "bob",
        "bbbb2222",
        "10.0.0.2",
        Some("store_unavailable"),
    )?;
    run(&ex).await?;
    assert_eq!(sink.deliveries().len(), 2);
    Ok(())
}

#[tokio::test]
async fn without_the_feature_the_page_says_why_and_a_viewer_changes_nothing() -> Result<(), Error> {
    let Some(url) = database("alerts_gate").await? else {
        return Ok(());
    };
    let gw = gateway("alerts_gate", &url, &licensed(&["members"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let page = owner.go(&gw.app, "GET", "/console/alerts", &[]).await?;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(page.text.contains("license_required"), "{}", page.text);
    let audit = owner.go(&gw.app, "GET", "/console/audit", &[]).await?;
    assert!(!audit.text.contains("/console/alerts"), "no nav entry");
    Ok(())
}

/// Saves a rule through the console, sending to channel 1.
async fn add_rule(
    owner: &mut Browser,
    gw: &Gateway,
    fields: &[(&str, &str)],
) -> Result<String, Error> {
    let mut form: Vec<(&str, &str)> = vec![
        ("action", "rule_save"),
        ("channels", "1"),
        ("cooldown", "60"),
    ];
    form.extend_from_slice(fields);
    Ok(owner
        .go(&gw.app, "POST", "/console/alerts", &form)
        .await?
        .text)
}

async fn webhook(owner: &mut Browser, gw: &Gateway, sink: &Sink) -> Result<(), Error> {
    let saved = owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "channel_save"),
                ("kind", "webhook"),
                ("name", "ops hook"),
                ("url", &format!("{}/in/alerts", sink.base)),
            ],
        )
        .await?;
    assert!(saved.text.contains("Saved channel 1"), "{}", saved.text);
    Ok(())
}

async fn execute(url: &str, sql: &str, params: &[&str]) -> Result<(), Error> {
    use gantry_server::store::tokio_postgres;
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
        .iter()
        .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();
    client.execute(sql, &params).await?;
    Ok(())
}

/// What the gateway's own counter has spent, as settled spend: the alert reads the counter enforcement reads.
async fn set_spent(url: &str, scope: &str, per: Period, usd: f64) -> Result<(), Error> {
    let label = per.label(&audit::timestamp());
    execute(
        url,
        &format!(
            "INSERT INTO gantry_spend (scope, per, period, spent) VALUES ($1, $2, $3, {usd}) \
             ON CONFLICT (scope, per, period) DO UPDATE SET spent = {usd}"
        ),
        &[scope, &per.word(), &label],
    )
    .await
}

fn usage(gw: &Gateway, id: &str) -> Result<(), Error> {
    write(
        gw,
        json!({ "event": "usage", "id": id, "person": "alice", "team": "payments", "key": "aaaa1111", "model": "m", "provider": "mock", "status": 200, "charged_usd": 1.0 }),
    )
}

#[tokio::test]
async fn a_percent_rule_fires_at_its_share_of_each_policy_budget_for_its_period()
-> Result<(), Error> {
    let Some(url) = database("alerts_percent").await? else {
        return Ok(());
    };
    // A period a fifth to three fifths through now, for the forecast: projected past the threshold, actual not yet.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let chosen = ["6h", "day", "week", "month"].into_iter().find_map(|p| {
        let per = Period::parse(p, None).ok()?;
        let (start, end) = per.window(now);
        let elapsed = (now - start) as f64 / (end - start) as f64;
        (0.2..0.6).contains(&elapsed).then_some((p, per, elapsed))
    });
    let forecast_per = chosen.map_or("day", |c| c.0);
    let policy = format!(
        "{}limits:\n  - {{ team: payments, budget: [{{ usd: 100, per: month }}, {{ usd: 10, per: {{ sliding: 24h }} }}] }}\n  - {{ person: alice, budget: {{ usd: 1000, per: {forecast_per} }} }}\n",
        crate::enterprise::testing::POLICY
    );
    let sink = Sink::start().await?;
    let (gw, ex) =
        crate::enterprise::siem::tests::quiet_policy("alerts_percent", &url, &["alerts"], &policy)?;
    let mut owner = Browser::admin(&gw.app).await?;
    webhook(&mut owner, &gw, &sink).await?;
    let added = add_rule(
        &mut owner,
        &gw,
        &[
            ("kind", "budget"),
            ("name_rule", "Payments 80%"),
            ("percent", "80"),
            ("scope", "team"),
            ("name", "payments"),
        ],
    )
    .await?;
    assert!(added.contains("Added rule"), "{added}");
    let added = add_rule(
        &mut owner,
        &gw,
        &[
            ("kind", "budget"),
            ("name_rule", "Alice forecast"),
            ("percent", "50"),
            ("scope", "person:alice"),
            ("forecast", "on"),
        ],
    )
    .await?;
    assert!(added.contains("Added rule"), "{added}");
    let refused = add_rule(
        &mut owner,
        &gw,
        &[
            ("kind", "budget"),
            ("name_rule", "bad"),
            ("percent", "80"),
            ("scope", "planet:mars"),
        ],
    )
    .await?;
    assert!(
        refused.contains("With a percent, scope is global, or org, team"),
        "{refused}"
    );

    let month = Period::Month;
    let sliding = Period::parse("sliding 24h", None)?;
    set_spent(&url, "team:payments", month, 79.0).await?;
    set_spent(&url, "team:payments", sliding, 9.0).await?;
    if let Some((_, per, elapsed)) = chosen {
        set_spent(&url, "person:alice", per, 500.0 * elapsed * 1.5).await?;
    }
    usage(&gw, "u1")?;
    run(&ex).await?;
    let hits: Vec<Value> = sink.deliveries().iter().map(|h| h.json()).collect();
    let payments: Vec<&Value> = hits
        .iter()
        .filter(|h| h["rule"] == "Payments 80%")
        .collect();
    assert_eq!(payments.len(), 1, "the sliding budget only: {hits:?}");
    assert_eq!(payments[0]["subject"], "team:payments|sliding:24h");
    let summary = payments[0]["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("$9.00 of its $10.00 budget for any 24 hours in the last 24 hours (90%)"),
        "{summary}"
    );
    assert_eq!(payments[0]["records"][0]["id"], "u1");
    if chosen.is_some() {
        let forecast = hits
            .iter()
            .find(|h| h["rule"] == "Alice forecast")
            .ok_or(format!("no forecast alert: {hits:?}"))?;
        assert!(
            forecast["summary"]
                .as_str()
                .unwrap_or_default()
                .contains("is forecast to spend"),
            "{forecast}"
        );
    } else {
        eprintln!("forecast not checked: every period is at its very start or end now");
    }

    // The month reaches 80%: its own alert, once for the month. The sliding one stays quiet for its quiet period.
    sink.clear();
    set_spent(&url, "team:payments", month, 81.0).await?;
    usage(&gw, "u2")?;
    run(&ex).await?;
    let hits: Vec<Value> = sink.deliveries().iter().map(|h| h.json()).collect();
    let payments: Vec<&Value> = hits
        .iter()
        .filter(|h| h["rule"] == "Payments 80%")
        .collect();
    assert_eq!(payments.len(), 1, "{hits:?}");
    assert_eq!(
        payments[0]["subject"],
        format!("team:payments|month|{}", month.label(&audit::timestamp()))
    );
    sink.clear();
    usage(&gw, "u3")?;
    run(&ex).await?;
    assert!(
        !sink
            .deliveries()
            .iter()
            .any(|h| h.json()["rule"] == "Payments 80%"),
        "once per period"
    );
    Ok(())
}

#[tokio::test]
async fn provider_errors_count_failures_that_were_not_retried() -> Result<(), Error> {
    let Some(url) = database("alerts_upstream").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("alerts_upstream", &url, &["alerts"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    webhook(&mut owner, &gw, &sink).await?;
    let added = add_rule(
        &mut owner,
        &gw,
        &[
            ("kind", "provider_errors"),
            ("name_rule", "Gone"),
            ("count", "3"),
            ("minutes", "10"),
            ("provider", "gone"),
        ],
    )
    .await?;
    assert!(added.contains("Added rule"), "{added}");
    // One failure with no retry: an upstream error record and nothing else. It counts, one of three.
    write(
        &gw,
        json!({ "event": "upstream_error", "id": "f1", "status": 502, "code": "upstream_unreachable", "provider": "gone", "tries": 1 }),
    )?;
    // A refusal Gantry made itself, not the provider's failure: not counted.
    write(
        &gw,
        json!({ "event": "upstream_error", "id": "f0", "status": 403, "code": "unknown_model", "provider": "gone", "tries": 0 }),
    )?;
    run(&ex).await?;
    assert!(sink.deliveries().is_empty());
    // Retried once: the attempts record has both tries, the upstream error the last. Two more: three.
    write(
        &gw,
        json!({ "event": "attempts", "id": "f2", "attempts": [{ "provider": "gone", "outcome": "upstream_timeout" }, { "provider": "gone", "outcome": "upstream_timeout" }] }),
    )?;
    write(
        &gw,
        json!({ "event": "upstream_error", "id": "f2", "status": 504, "code": "upstream_timeout", "provider": "gone", "tries": 2 }),
    )?;
    run(&ex).await?;
    let hits: Vec<Value> = sink.deliveries().iter().map(|h| h.json()).collect();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["subject"], "provider:gone");
    let summary = hits[0]["summary"].as_str().unwrap_or_default();
    assert!(summary.starts_with("3 in the last 10 minutes"), "{summary}");
    assert!(summary.contains("upstream_timeout"), "{summary}");
    Ok(())
}
