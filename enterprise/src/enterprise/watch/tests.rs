//! Watch mode as the Cloudflare app's test checks it (cloud/tests/test_claude_watch.py): a token, exports accepted,
//! a wrong token refused, the person with sessions, cost and lines, the rejected tool call and the API error, prompt
//! text never kept. Plus what the self-hosted port adds: protobuf, expiry, repeats, cumulative metrics, the audit
//! chain, the request index, coverage, and the license gate. Against a real Postgres.
//!
//! The `claude-code-2.1.325-*` fixtures are real exports of Claude Code 2.1.325, taken by `fixtures/capture.py`
//! against a receiver and a mock model API on one machine (no call left it), once as JSON and once as protobuf,
//! with `OTEL_LOG_USER_PROMPTS=1` so the prompt text is there to be dropped. One prompt, one model request:
//! 1,200 input, 40 output, 5,000 cache read and 300 cache write tokens, $0.00405.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::otlp;
use crate::enterprise::testing::*;

const LOGS_JSON: &[u8] = include_bytes!("fixtures/claude-code-2.1.325-logs.json");
const METRICS_JSON: &[u8] = include_bytes!("fixtures/claude-code-2.1.325-metrics.json");
const LOGS_PB: &[u8] = include_bytes!("fixtures/claude-code-2.1.325-logs.pb");
const METRICS_PB: &[u8] = include_bytes!("fixtures/claude-code-2.1.325-metrics.pb");
const PROTOBUF: &str = "application/x-protobuf";
const JSON: &str = "application/json";
const MAYA: &str = "maya.cohen@example.com";

struct Reply {
    status: StatusCode,
    body: Value,
    text: String,
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    kind: &str,
    body: Vec<u8>,
) -> Result<Reply, Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, kind);
    if !token.is_empty() {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app.clone().oneshot(request.body(Body::from(body))?).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(Reply {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    })
}

/// An admin API call: noa's admin key, JSON.
async fn admin(app: &Router, method: &str, path: &str, body: Value) -> Result<Reply, Error> {
    let body = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    send(app, method, path, ADMIN_KEY, JSON, body).await
}

async fn new_token(app: &Router, body: Value) -> Result<(String, String), Error> {
    let made = admin(app, "POST", "/console/watch/tokens", body).await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
    let field = |name: &str| made.body[name].as_str().unwrap_or_default().to_string();
    assert!(
        field("token").starts_with("enterplace_watch_")
            && field("token").len() == super::PREFIX.len() + 64
    );
    Ok((field("id"), field("token")))
}

async fn summary(app: &Router) -> Result<Reply, Error> {
    admin(app, "GET", "/console/watch/summary.json", Value::Null).await
}

fn watch_records(gw: &Gateway) -> Result<Vec<Value>, Error> {
    gw.log.flush();
    Ok(std::fs::read_to_string(&gw.audit)?
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "watch")
        .collect())
}

fn kv(key: &str, value: Value) -> Value {
    let value = match &value {
        Value::String(_) => json!({ "stringValue": value }),
        Value::Bool(_) => json!({ "boolValue": value }),
        v if v.is_f64() => json!({ "doubleValue": value }),
        _ => json!({ "intValue": value }),
    };
    json!({ "key": key, "value": value })
}

/// A resource as Claude Code on a Claude Team seat describes itself, per Anthropic's monitoring page.
fn resource(email: &str, session: &str) -> Value {
    json!({ "attributes": [
        kv("service.name", json!("claude-code")), kv("service.version", json!("2.1.325")),
        kv("user.email", json!(email)), kv("organization.id", json!("org-x")),
        kv("user.account_uuid", json!("acc-1")), kv("session.id", json!(session)), kv("terminal.type", json!("vscode")),
    ] })
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

fn sum(name: &str, temporality: u64, start: u64, time: u64, points: &[(f64, Value)]) -> Value {
    let points: Vec<Value> = points
        .iter()
        .map(|(value, attrs)| json!({ "startTimeUnixNano": start.to_string(), "timeUnixNano": time.to_string(), "asDouble": value, "attributes": attrs }))
        .collect();
    json!({ "name": name, "sum": { "aggregationTemporality": temporality, "isMonotonic": true, "dataPoints": points } })
}

fn metrics_body(email: &str, session: &str, metrics: Vec<Value>) -> Vec<u8> {
    json!({ "resourceMetrics": [{ "resource": resource(email, session), "scopeMetrics": [{ "metrics": metrics }] }] })
        .to_string()
        .into_bytes()
}

fn event(name: &str, sequence: u64, time: u64, mut attrs: Vec<Value>) -> Value {
    attrs.push(kv("event.name", json!(name)));
    attrs.push(kv("event.sequence", json!(sequence)));
    json!({ "timeUnixNano": time.to_string(), "body": { "stringValue": format!("claude_code.{name}") }, "attributes": attrs })
}

fn logs_body(email: &str, session: &str, records: Vec<Value>) -> Vec<u8> {
    json!({ "resourceLogs": [{ "resource": resource(email, session), "scopeLogs": [{ "logRecords": records }] }] })
        .to_string()
        .into_bytes()
}

/// A sum of the summary: of the row of `list` (`people`, `models`, `tools`) whose `key` is `of`.
fn metric(reply: &Value, list: &str, key: &str, of: &str, metric: &str) -> f64 {
    reply[list]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row[key] == of)
        .and_then(|row| row["metrics"][metric].as_f64())
        .unwrap_or(0.0)
}

#[test]
fn the_real_export_reads_the_same_as_json_and_as_protobuf() -> Result<(), Error> {
    for (points, events) in [
        (
            otlp::metrics_json(METRICS_JSON)?,
            otlp::logs_json(LOGS_JSON)?,
        ),
        (otlp::metrics_proto(METRICS_PB)?, otlp::logs_proto(LOGS_PB)?),
    ] {
        let value = |metric: &str, kind: &str| -> f64 {
            points
                .iter()
                .filter(|p| {
                    p.metric == metric
                        && (kind.is_empty() || p.attrs.get("type") == Some(&json!(kind)))
                })
                .map(|p| p.value)
                .sum()
        };
        assert_eq!(value("claude_code.session.count", ""), 1.0);
        assert_eq!(value("claude_code.cost.usage", ""), 0.00405);
        assert_eq!(value("claude_code.token.usage", "input"), 1200.0);
        assert_eq!(value("claude_code.token.usage", "output"), 40.0);
        assert_eq!(value("claude_code.token.usage", "cacheRead"), 5000.0);
        assert_eq!(value("claude_code.token.usage", "cacheCreation"), 300.0);
        let cost = points
            .iter()
            .find(|p| p.metric == "claude_code.cost.usage")
            .ok_or("no cost")?;
        assert!(!cost.cumulative && cost.time_ns > cost.start_ns && cost.start_ns > 0);
        assert_eq!(cost.attrs.get("model"), Some(&json!("claude-sonnet-5-5")));
        // Resource attributes reach every point and event.
        assert_eq!(cost.attrs.get("user.email"), Some(&json!(MAYA)));
        assert_eq!(cost.attrs.get("service.version"), Some(&json!("2.1.325")));

        let named = |name: &str| {
            events
                .iter()
                .find(|e| e.body == format!("claude_code.{name}"))
        };
        let request = named("api_request").ok_or("no api_request")?;
        assert_eq!(request.attrs.get("event.name"), Some(&json!("api_request")));
        assert_eq!(request.attrs.get("input_tokens"), Some(&json!(1200)));
        assert_eq!(request.attrs.get("cost_usd"), Some(&json!(0.00405)));
        assert!(request.time_ns > 1_700_000_000_000_000_000);
        let prompt = named("user_prompt").ok_or("no user_prompt")?;
        assert_eq!(prompt.attrs.get("prompt_length"), Some(&json!("43")));
    }
    // Not protobuf, and protobuf cut short, are errors, never a panic or a partial read taken as whole.
    assert!(otlp::metrics_proto(b"{\"resourceMetrics\": []}").is_err());
    assert!(otlp::logs_proto(&LOGS_PB[..LOGS_PB.len() - 7]).is_err());
    assert!(otlp::logs_json(b"\x0a\x03abc").is_err());
    Ok(())
}

#[tokio::test]
async fn a_real_claude_code_export_gives_the_person_tokens_and_cost_once() -> Result<(), Error> {
    let Some(url) = database("watch_real").await? else {
        return Ok(());
    };
    let gw = gateway("watch_real", &url, &licensed(&["watch"]))?;
    let (id, token) = new_token(
        &gw.app,
        json!({ "label": "claude-team", "team": "payments" }),
    )
    .await?;

    let empty = summary(&gw.app).await?;
    assert_eq!(
        empty.body["steps"]["see"]["status"],
        "waiting for the first export"
    );

    // As Claude Code sends by default: protobuf.
    let sent = send(
        &gw.app,
        "POST",
        "/otlp/v1/metrics",
        &token,
        PROTOBUF,
        METRICS_PB.to_vec(),
    )
    .await?;
    assert_eq!((sent.status, sent.text.as_str()), (StatusCode::OK, ""));
    let sent = send(
        &gw.app,
        "POST",
        "/otlp/v1/logs",
        &token,
        PROTOBUF,
        LOGS_PB.to_vec(),
    )
    .await?;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    // Claude Code retries an export it got no answer to: the same bytes count once.
    for (path, body) in [("/otlp/v1/metrics", METRICS_PB), ("/otlp/v1/logs", LOGS_PB)] {
        let again = send(&gw.app, "POST", path, &token, PROTOBUF, body.to_vec()).await?;
        assert_eq!(again.status, StatusCode::OK, "{}", again.text);
    }

    let seen = summary(&gw.app).await?;
    assert_eq!(seen.status, StatusCode::OK, "{}", seen.text);
    let person = &seen.body["people"][0];
    assert_eq!(
        (person["person"].as_str(), person["team"].as_str()),
        (Some(MAYA), Some("payments")),
        "{}",
        seen.text
    );
    for (name, want) in [
        ("sessions", 1.0),
        ("cost_usd", 0.00405),
        ("tokens_input", 1200.0),
        ("tokens_output", 40.0),
        ("tokens_cache_read", 5000.0),
        ("tokens_cache_creation", 300.0),
        ("api_requests", 1.0),
        ("prompts", 1.0),
        ("prompt_chars", 43.0),
        // The prompt, and the answer on the assistant_response event, which is not kept at all.
        ("content_dropped", 2.0),
    ] {
        assert_eq!(
            person["metrics"][name],
            json!(want),
            "{name}: {}",
            seen.text
        );
    }
    assert_eq!(
        metric(
            &seen.body,
            "models",
            "model",
            "claude-sonnet-5-5",
            "cost_usd"
        ),
        0.00405
    );
    assert_eq!(seen.body["steps"]["see"]["status"], "on");
    assert_eq!(seen.body["steps"]["know"]["status"], "on");
    assert_eq!(
        seen.body["steps"]["limit"]["status"],
        "needs API traffic through Enterplace"
    );
    assert_eq!(
        seen.body["steps"]["protect"]["status"],
        "needs API traffic through Enterplace"
    );

    // The same session's other run, sent as JSON: a second session, counted beside the first.
    for (path, body) in [
        ("/otlp/v1/metrics", METRICS_JSON),
        ("/otlp/v1/logs", LOGS_JSON),
    ] {
        let sent = send(&gw.app, "POST", path, &token, JSON, body.to_vec()).await?;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
        assert_eq!(sent.body, json!({ "partialSuccess": {} }));
    }
    let both = summary(&gw.app).await?;
    assert_eq!(
        both.body["totals"]["tokens_input"],
        json!(2400.0),
        "{}",
        both.text
    );
    assert_eq!(both.body["totals"]["sessions"], json!(2.0));

    // The chain: one record per kept event and one for each session's metrics. Never the prompt.
    let records = watch_records(&gw)?;
    let kinds: Vec<&str> = records.iter().filter_map(|r| r["kind"].as_str()).collect();
    assert_eq!(
        kinds.iter().filter(|k| **k == "api_request").count(),
        2,
        "{kinds:?}"
    );
    assert_eq!(kinds.iter().filter(|k| **k == "user_prompt").count(), 2);
    assert_eq!(kinds.iter().filter(|k| **k == "metrics").count(), 2);
    assert_eq!(
        kinds.len(),
        6,
        "plugin and settings events are dropped: {kinds:?}"
    );
    let request = records
        .iter()
        .find(|r| r["kind"] == "api_request")
        .ok_or("no record")?;
    assert_eq!(
        (
            request["person"].as_str(),
            request["team"].as_str(),
            request["source"].as_str(),
            request["token"].as_str()
        ),
        (
            Some(MAYA),
            Some("payments"),
            Some("watch"),
            Some(id.as_str())
        )
    );
    assert_eq!(
        (
            &request["model"],
            &request["provider"],
            &request["input_tokens"],
            &request["output_tokens"],
            &request["cost_usd"]
        ),
        (
            &json!("claude-sonnet-5-5"),
            &json!("anthropic"),
            &json!(1200),
            &json!(40),
            &json!(0.00405)
        )
    );
    assert_eq!(request["user_agent"], "claude-code/2.1.325");
    let prompt = records
        .iter()
        .find(|r| r["kind"] == "user_prompt")
        .ok_or("no prompt record")?;
    assert_eq!(
        (&prompt["prompt_length"], &prompt["content_dropped"]),
        (&json!(43), &json!(true))
    );
    let totals = &records
        .iter()
        .find(|r| r["kind"] == "metrics")
        .ok_or("no metrics record")?["totals"];
    assert_eq!(
        totals["tokens_input:claude-sonnet-5-5"],
        json!(1200.0),
        "{totals}"
    );
    assert!(enterplace_core::audit::verify(&gw.audit).is_ok());

    // The text Claude Code was told to send is nowhere: not in the chain, the answers or the tables.
    let chain = std::fs::read_to_string(&gw.audit)?;
    let tables = {
        use enterplace_server::store::tokio_postgres;
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        let row = client
            .query_one(
                "SELECT coalesce((SELECT string_agg(d::text, ' ') FROM enterprise_watch_daily d), '') || \
                 coalesce((SELECT string_agg(s::text, ' ') FROM enterprise_watch_series s), '') || \
                 coalesce((SELECT string_agg(k::text, ' ') FROM enterprise_watch_seen k), '')",
                &[],
            )
            .await?;
        row.try_get::<_, String>(0)?
    };
    assert!(tables.contains(MAYA), "the tables were read");
    for kept in [&chain, &both.text, &tables] {
        assert!(!kept.contains("PROMPT-SECRET") && !kept.contains("single word"));
    }
    Ok(())
}

#[tokio::test]
async fn the_documented_shapes_give_tools_lines_commits_errors_and_cumulative_growth()
-> Result<(), Error> {
    let Some(url) = database("watch_docs").await? else {
        return Ok(());
    };
    let gw = gateway("watch_docs", &url, &licensed(&["watch"]))?;
    let (_, token) = new_token(&gw.app, json!({ "label": "team", "team": "payments" })).await?;
    let (now, model) = (now_ns(), kv("model", json!("claude-sonnet-5-5")));
    let start = now - 60_000_000_000;

    // The Cloudflare test's metrics, as deltas.
    let metrics = metrics_body(
        "Dana@Acme.co",
        "s-1",
        vec![
            sum(
                "claude_code.cost.usage",
                1,
                start,
                now,
                &[(0.75, json!([model.clone()]))],
            ),
            sum(
                "claude_code.token.usage",
                1,
                start,
                now,
                &[(5000.0, json!([kv("type", json!("input")), model.clone()]))],
            ),
            sum(
                "claude_code.session.count",
                1,
                start,
                now,
                &[(2.0, json!([]))],
            ),
            sum(
                "claude_code.lines_of_code.count",
                1,
                start,
                now,
                &[
                    (120.0, json!([kv("type", json!("added"))])),
                    (7.0, json!([kv("type", json!("removed"))])),
                ],
            ),
            sum(
                "claude_code.commit.count",
                1,
                start,
                now,
                &[(3.0, json!([]))],
            ),
            sum(
                "claude_code.pull_request.count",
                1,
                start,
                now,
                &[(1.0, json!([]))],
            ),
            sum(
                "claude_code.code_edit_tool.decision",
                1,
                start,
                now,
                &[
                    (
                        4.0,
                        json!([
                            kv("tool_name", json!("Edit")),
                            kv("decision", json!("accept"))
                        ]),
                    ),
                    (
                        1.0,
                        json!([
                            kv("tool_name", json!("Write")),
                            kv("decision", json!("reject"))
                        ]),
                    ),
                ],
            ),
            sum(
                "claude_code.active_time.total",
                1,
                start,
                now,
                &[(90.5, json!([kv("type", json!("user"))]))],
            ),
            sum("some.other.metric", 1, start, now, &[(9.0, json!([]))]),
        ],
    );
    let sent = send(&gw.app, "POST", "/otlp/v1/metrics", &token, JSON, metrics).await?;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);

    let logs = logs_body(
        "Dana@Acme.co",
        "s-1",
        vec![
            event(
                "api_request",
                1,
                now,
                vec![
                    model.clone(),
                    kv("cost_usd", json!(0.0123)),
                    kv("input_tokens", json!(1200)),
                    kv("output_tokens", json!(300)),
                    kv("duration_ms", json!(2400)),
                ],
            ),
            event(
                "user_prompt",
                2,
                now,
                vec![
                    kv("prompt_length", json!("42")),
                    kv("prompt", json!("PROMPT-SECRET do the thing")),
                ],
            ),
            event(
                "tool_decision",
                3,
                now,
                vec![
                    kv("tool_name", json!("Bash")),
                    kv("decision", json!("reject")),
                    kv("source", json!("user_reject")),
                    kv(
                        "tool_parameters",
                        json!("{\"command\":\"rm -rf PROMPT-SECRET\"}"),
                    ),
                ],
            ),
            event(
                "tool_decision",
                4,
                now,
                vec![
                    kv("tool_name", json!("Bash")),
                    kv("decision", json!("accept")),
                    kv("source", json!("config")),
                ],
            ),
            event(
                "tool_decision",
                5,
                now,
                vec![
                    kv("tool_name", json!("Read")),
                    kv("decision", json!("accept")),
                    kv("source", json!("config")),
                ],
            ),
            event(
                "tool_result",
                6,
                now,
                vec![
                    kv("tool_name", json!("Bash")),
                    kv("success", json!("false")),
                    kv("duration_ms", json!(12)),
                ],
            ),
            event(
                "tool_result",
                7,
                now,
                vec![
                    kv("tool_name", json!("Read")),
                    kv("success", json!("true")),
                    kv("duration_ms", json!(3)),
                ],
            ),
            event(
                "api_error",
                8,
                now,
                vec![
                    model.clone(),
                    kv("status_code", json!(529)),
                    kv("error", json!("overloaded")),
                ],
            ),
            event("api_refusal", 9, now, vec![model.clone()]),
            event(
                "hook_registered",
                10,
                now,
                vec![kv("hook_event", json!("PreToolUse"))],
            ),
        ],
    );
    let sent = send(&gw.app, "POST", "/otlp/v1/logs", &token, JSON, logs).await?;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);

    let seen = summary(&gw.app).await?;
    let dana = |name: &str| metric(&seen.body, "people", "person", "dana@acme.co", name);
    for (name, want) in [
        ("cost_usd", 0.75),
        ("tokens_input", 5000.0),
        ("sessions", 2.0),
        ("lines_added", 120.0),
        ("lines_removed", 7.0),
        ("commits", 3.0),
        ("pull_requests", 1.0),
        ("edits_accepted", 4.0),
        ("edits_rejected", 1.0),
        ("active_seconds", 90.5),
        ("api_requests", 1.0),
        ("api_errors", 1.0),
        ("api_refusals", 1.0),
        ("prompts", 1.0),
        ("prompt_chars", 42.0),
        ("tool_accepted", 2.0),
        ("tool_rejected", 1.0),
        ("tool_runs", 2.0),
        ("tool_failures", 1.0),
        ("content_dropped", 2.0),
    ] {
        assert_eq!(dana(name), want, "{name}: {}", seen.text);
    }
    let tool = |tool: &str, name: &str| metric(&seen.body, "tools", "tool", tool, name);
    assert_eq!(
        (
            tool("Bash", "tool_accepted"),
            tool("Bash", "tool_rejected"),
            tool("Bash", "tool_failures")
        ),
        (1.0, 1.0, 1.0)
    );
    assert_eq!(
        (
            tool("Read", "tool_accepted"),
            tool("Edit", "edits_accepted"),
            tool("Write", "edits_rejected")
        ),
        (1.0, 4.0, 1.0)
    );

    let records = watch_records(&gw)?;
    let of = |kind: &str| {
        records
            .iter()
            .filter(|r| r["kind"] == kind)
            .collect::<Vec<_>>()
    };
    let rejected = of("tool_decision")
        .into_iter()
        .find(|r| r["decision"] == "reject")
        .ok_or("no rejected tool")?;
    assert_eq!(
        (
            &rejected["tool"],
            &rejected["decision_source"],
            &rejected["content_dropped"]
        ),
        (&json!("Bash"), &json!("user_reject"), &json!(true))
    );
    let error = of("api_error").into_iter().next().ok_or("no api_error")?;
    assert_eq!(
        (&error["status"], &error["error"], &error["person"]),
        (&json!(529), &json!("overloaded"), &json!("dana@acme.co"))
    );
    assert!(of("hook_registered").is_empty());
    assert!(!std::fs::read_to_string(&gw.audit)?.contains("PROMPT-SECRET"));

    // A backend told to send cumulative totals: 5, then 8, then 8 again, then a new process starting from 2.
    let commits = |start: u64, time: u64, total: f64| {
        metrics_body(
            "eli@acme.co",
            "s-2",
            vec![sum(
                "claude_code.commit.count",
                2,
                start,
                time,
                &[(total, json!([]))],
            )],
        )
    };
    for (start, time, total) in [
        (start, now, 5.0),
        (start, now + 1_000, 8.0),
        (start, now + 1_000, 8.0),
        (now + 2_000, now + 3_000, 2.0),
    ] {
        let sent = send(
            &gw.app,
            "POST",
            "/otlp/v1/metrics",
            &token,
            JSON,
            commits(start, time, total),
        )
        .await?;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    }
    let seen = summary(&gw.app).await?;
    assert_eq!(
        metric(&seen.body, "people", "person", "eli@acme.co", "commits"),
        10.0,
        "{}",
        seen.text
    );

    // One person's token: the person is the token's, whatever the export says.
    let (_, own) = new_token(&gw.app, json!({ "label": "noa's laptop", "person": "noa" })).await?;
    let sent = send(
        &gw.app,
        "POST",
        "/otlp/v1/logs",
        &own,
        JSON,
        logs_body(
            "someone.else@acme.co",
            "s-3",
            vec![event("api_request", 1, now, vec![model])],
        ),
    )
    .await?;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    let seen = summary(&gw.app).await?;
    assert_eq!(
        metric(&seen.body, "people", "person", "noa", "api_requests"),
        1.0,
        "{}",
        seen.text
    );
    assert!(!seen.text.contains("someone.else"));
    Ok(())
}

#[tokio::test]
async fn a_missing_wrong_revoked_or_expired_token_and_a_bad_export_are_refused() -> Result<(), Error>
{
    let Some(url) = database("watch_refuse").await? else {
        return Ok(());
    };
    let gw = gateway("watch_refuse", &url, &licensed(&["watch"]))?;
    let post = |token: &str, kind: &str, body: &[u8]| {
        let (app, token, kind, body) = (
            gw.app.clone(),
            token.to_string(),
            kind.to_string(),
            body.to_vec(),
        );
        async move { send(&app, "POST", "/otlp/v1/logs", &token, &kind, body).await }
    };
    let (id, token) = new_token(
        &gw.app,
        json!({ "label": "team", "team": "payments", "days": 30 }),
    )
    .await?;
    let (old_id, old) = new_token(&gw.app, json!({ "label": "old" })).await?;

    let zeros = format!("enterplace_watch_{}", "0".repeat(64));
    for bad in ["", "enterplace_dev_abc", zeros.as_str(), ADMIN_KEY] {
        let refused = post(bad, PROTOBUF, LOGS_PB).await?;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{bad}");
        assert_eq!(
            refused.body["error"]["code"], "invalid_token",
            "{}",
            refused.text
        );
        assert!(
            refused.text.contains("OTEL_EXPORTER_OTLP_HEADERS"),
            "{}",
            refused.text
        );
    }

    // What is not OTLP over HTTP is refused with the fix, after the token is checked.
    let grpc = post(&token, "application/grpc", LOGS_PB).await?;
    assert_eq!(grpc.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(
        grpc.text
            .contains("OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf"),
        "{}",
        grpc.text
    );
    for (kind, body) in [
        (PROTOBUF, &b"{\"resourceLogs\": []}"[..]),
        (JSON, LOGS_PB),
        (PROTOBUF, &LOGS_PB[..LOGS_PB.len() - 7]),
    ] {
        let bad = post(&token, kind, body).await?;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
        assert_eq!(bad.body["error"]["code"], "invalid_export");
    }
    let large = post(&token, JSON, &vec![b' '; super::MAX_BODY + 1]).await?;
    assert_eq!(
        large.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        large.text
    );
    // gzip is taken (a_gzip_export_is_read_and_one_that_unpacks_too_large_is_refused); another encoding is not.
    let brotli = gw
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/otlp/v1/logs")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, PROTOBUF)
                .header(header::CONTENT_ENCODING, "br")
                .body(Body::from(LOGS_PB.to_vec()))?,
        )
        .await?;
    assert_eq!(brotli.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(watch_records(&gw)?.is_empty(), "nothing refused was kept");

    // Revoked: refused from then on. Revoking it again, or an unknown one, is not found.
    assert_eq!(post(&old, PROTOBUF, LOGS_PB).await?.status, StatusCode::OK);
    let revoked = admin(
        &gw.app,
        "DELETE",
        &format!("/console/watch/tokens/{old_id}"),
        Value::Null,
    )
    .await?;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.text);
    assert_eq!(
        post(&old, PROTOBUF, LOGS_PB).await?.body["error"]["code"],
        "invalid_token"
    );
    let again = admin(
        &gw.app,
        "DELETE",
        &format!("/console/watch/tokens/{old_id}"),
        Value::Null,
    )
    .await?;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    // Expired: refused, saying when and what to do.
    {
        use enterplace_server::store::tokio_postgres;
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
            .execute("UPDATE enterprise_watch_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1", &[&id])
            .await?;
        let hashes: i64 = client
            .query_one("SELECT count(*) FROM enterprise_watch_tokens WHERE token_sha256 ~ '^[0-9a-f]{64}$' AND token_sha256 <> $1", &[&token])
            .await?
            .try_get(0)?;
        assert_eq!(hashes, 2, "tokens are kept as hashes");
    }
    let expired = post(&token, PROTOBUF, LOGS_PB).await?;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        expired.body["error"]["code"], "token_expired",
        "{}",
        expired.text
    );

    // The list shows each token's state and never the token.
    let listed = admin(&gw.app, "GET", "/console/watch/tokens", Value::Null).await?;
    let state = |id: &str| {
        listed.body["tokens"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|t| t["id"] == id)
            .map(|t| t["status"].clone())
    };
    assert_eq!(
        (state(&id), state(&old_id)),
        (Some(json!("expired")), Some(json!("revoked"))),
        "{}",
        listed.text
    );
    assert!(!listed.text.contains(&token) && !listed.text.contains(&old));

    // Who may: an admin key or a console session. And what a token may be.
    let nobody = send(
        &gw.app,
        "GET",
        "/console/watch/tokens",
        "enterplace_not_a_key",
        JSON,
        Vec::new(),
    )
    .await?;
    assert_eq!(nobody.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(
            &gw.app,
            "GET",
            "/console/watch/summary.json",
            &token,
            JSON,
            Vec::new()
        )
        .await?
        .status,
        StatusCode::UNAUTHORIZED
    );
    for bad in [
        json!({}),
        json!({ "label": "x", "team": "not a team" }),
        json!({ "label": "x", "days": 4000 }),
    ] {
        let refused = admin(&gw.app, "POST", "/console/watch/tokens", bad).await?;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    }

    // Every change is an admin record, the refused ones with their code.
    gw.log.flush();
    let actions: Vec<(String, String)> = std::fs::read_to_string(&gw.audit)?
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "admin")
        .map(|r| {
            (
                r["action"].as_str().unwrap_or_default().to_string(),
                r["code"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let count = |action: &str, code: &str| {
        actions
            .iter()
            .filter(|(a, c)| a == action && c == code)
            .count()
    };
    assert_eq!(
        (
            count("watch_token_created", ""),
            count("watch_token_created", "invalid_request")
        ),
        (2, 3),
        "{actions:?}"
    );
    assert_eq!(count("watch_token_revoked", ""), 2);
    Ok(())
}

#[tokio::test]
async fn watched_requests_are_in_usage_the_request_log_analytics_and_coverage() -> Result<(), Error>
{
    let Some(url) = database("watch_shows").await? else {
        return Ok(());
    };
    let gw = gateway("watch_shows", &url, &licensed(&["watch"]))?;
    let (_, token) = new_token(&gw.app, json!({ "label": "team", "team": "payments" })).await?;
    // A request through the gateway, beside the watched one.
    gw.log.append(&enterplace_core::audit::Entry {
        id: "D1",
        person: Some("noa"),
        team: Some("platform"),
        user_agent: Some("claude-cli/2.0.14 (external, cli)"),
        allowed: true,
        method: "POST",
        path: "/v1/messages",
        ..Default::default()
    })?;
    for (path, body) in [("/otlp/v1/metrics", METRICS_PB), ("/otlp/v1/logs", LOGS_PB)] {
        assert_eq!(
            send(&gw.app, "POST", path, &token, PROTOBUF, body.to_vec())
                .await?
                .status,
            StatusCode::OK
        );
    }

    // /admin/usage sums the store's request index, which the records reach with the copier's next pass.
    let mut tries = 0;
    let usage = loop {
        let usage = admin(&gw.app, "GET", "/admin/usage?group_by=source", Value::Null).await?;
        assert_eq!(usage.status, StatusCode::OK, "{}", usage.text);
        tries += 1;
        if usage.body["totals"]["requests"] == 2 || tries == 100 {
            break usage;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let group = |body: &Value, by: &str, value: &str| -> Value {
        body["groups"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|g| g[by] == value)
            .cloned()
            .unwrap_or(Value::Null)
    };
    let watched = group(&usage.body, "source", "watch");
    assert_eq!(
        (
            &watched["requests"],
            &watched["input_tokens"],
            &watched["output_tokens"],
            &watched["spend_usd"]
        ),
        (&json!(1), &json!(1200), &json!(40), &json!(0.00405)),
        "{}",
        usage.text
    );
    let people = admin(
        &gw.app,
        "GET",
        "/admin/usage?group_by=person&source=watch",
        Value::Null,
    )
    .await?;
    assert_eq!(
        group(&people.body, "person", MAYA)["spend_usd"],
        json!(0.00405),
        "{}",
        people.text
    );
    assert!(
        group(&people.body, "person", "noa").is_null(),
        "source=watch leaves gateway traffic out"
    );
    let tools = admin(&gw.app, "GET", "/admin/usage?group_by=agent", Value::Null).await?;
    assert_eq!(
        group(&tools.body, "agent", "claude-code")["requests"],
        json!(2),
        "{}",
        tools.text
    );

    // The console's Requests page and the Analytics API, filtered and ranked by the new dimension.
    let mut owner = Browser::admin(&gw.app).await?;
    let requests = owner
        .go(&gw.app, "GET", "/console/requests?source=watch", &[])
        .await?;
    assert_eq!(requests.status, StatusCode::OK);
    assert!(
        requests.text.contains(MAYA) && requests.text.contains("claude-sonnet-5-5"),
        "{}",
        requests.text
    );
    let analytics = owner
        .go(&gw.app, "GET", "/console/api/analytics?by=source", &[])
        .await?;
    assert_eq!(analytics.status, StatusCode::OK);
    assert!(
        analytics.text.contains(r#""value":"watch""#),
        "{}",
        analytics.text
    );

    // `enterplace audit coverage` reads the chain: the watched person beside the routed one.
    gw.log.flush();
    let coverage = enterplace_core::coverage::traffic(&gw.audit)?;
    let watched = coverage
        .get(&(
            MAYA.to_string(),
            enterplace_core::coverage::WATCHED.to_string(),
        ))
        .ok_or("maya is not covered")?;
    assert_eq!(
        (watched.requests, watched.refused, watched.team.as_str()),
        (1, 0, "payments")
    );
    assert_ne!(watched.last_seen, "never");
    assert_eq!(
        coverage
            .get(&("noa".to_string(), "claude-code".to_string()))
            .map(|r| r.requests),
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn without_the_feature_watch_answers_license_required_and_makes_no_tables()
-> Result<(), Error> {
    let others = ["members", "scim", "siem", "retention", "alerts", "devices"];
    for (n, status) in [unlicensed(), licensed(&others)].iter().enumerate() {
        let test = format!("watch_locked{n}");
        let Some(url) = database(&test).await? else {
            return Ok(());
        };
        let gw = gateway(&test, &url, status)?;
        for (method, path) in [
            ("POST", "/otlp/v1/metrics"),
            ("POST", "/otlp/v1/logs"),
            ("GET", "/console/watch/tokens"),
            ("POST", "/console/watch/tokens"),
            ("GET", "/console/watch/summary.json"),
        ] {
            let answer = send(
                &gw.app,
                method,
                path,
                ADMIN_KEY,
                PROTOBUF,
                METRICS_PB.to_vec(),
            )
            .await?;
            assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(
                answer.body["error"]["code"], "license_required",
                "{}",
                answer.text
            );
        }
        use enterplace_server::store::tokio_postgres;
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        let tables: i64 = client
            .query_one("SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'enterprise_watch%'", &[])
            .await?
            .try_get(0)?;
        assert_eq!(tables, 0);
    }
    Ok(())
}

#[tokio::test]
async fn the_watch_tables_follow_retention_and_legal_hold() -> Result<(), Error> {
    let Some(url) = database("watch_retention").await? else {
        return Ok(());
    };
    let gw = gateway("watch_retention", &url, &licensed(&["watch", "retention"]))?;
    let (_, token) = new_token(&gw.app, json!({ "label": "team" })).await?;
    use enterplace_server::store::tokio_postgres;
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    let old = "INSERT INTO enterprise_watch_daily (day, person, metric, value) VALUES (current_date - 400, 'old@acme.co', 'sessions', 1)";
    let left = || async {
        client
            .query_one(
                "SELECT count(*) FROM enterprise_watch_daily WHERE person = 'old@acme.co'",
                &[],
            )
            .await?
            .try_get::<_, i64>(0)
    };
    // Under legal hold nothing kept is deleted, however old.
    client.batch_execute(old).await?;
    client
        .batch_execute("UPDATE enterprise_export_settings SET legal_hold = true")
        .await?;
    assert_eq!(
        send(
            &gw.app,
            "POST",
            "/otlp/v1/metrics",
            &token,
            PROTOBUF,
            METRICS_PB.to_vec()
        )
        .await?
        .status,
        StatusCode::OK
    );
    assert_eq!(left().await?, 1);

    // Without it, the next export's pass (a new gateway: the pass runs once an hour) deletes what is past the days.
    client
        .batch_execute("UPDATE enterprise_export_settings SET legal_hold = false")
        .await?;
    client.batch_execute("DELETE FROM enterplace_keys").await?;
    let gw = gateway("watch_retention", &url, &licensed(&["watch", "retention"]))?;
    assert_eq!(
        send(
            &gw.app,
            "POST",
            "/otlp/v1/logs",
            &token,
            PROTOBUF,
            LOGS_PB.to_vec()
        )
        .await?
        .status,
        StatusCode::OK
    );
    assert_eq!(left().await?, 0);
    let kept: i64 = client
        .query_one("SELECT count(*) FROM enterprise_watch_daily", &[])
        .await?
        .try_get(0)?;
    assert!(kept > 0, "today's sums stay");
    Ok(())
}

#[test]
fn setup_prints_the_managed_settings_anthropic_documents() -> Result<(), Error> {
    let args = |list: &[&str]| list.iter().map(|a| (*a).to_string()).collect::<Vec<_>>();
    let token = format!("enterplace_watch_{}", "a".repeat(64));
    let out = super::setup(&args(&[
        "setup",
        "--gateway",
        "https://enterplace.example.com/",
        "--team",
        "payments",
        "--token",
        &token,
    ]))?;
    let block: Value = serde_json::from_str(
        out.split_once("\n{")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| format!("{{{body}\n}}"))
            .ok_or("no settings block")?
            .as_str(),
    )?;
    assert_eq!(
        block,
        json!({ "env": {
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_METRICS_EXPORTER": "otlp",
            "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://enterplace.example.com/otlp",
            "OTEL_EXPORTER_OTLP_HEADERS": format!("Authorization=Bearer {token}"),
        } })
    );
    assert!(
        out.contains("team payments")
            && out.contains("/Library/Application Support/ClaudeCode/managed-settings.json")
    );
    assert!(
        out.contains("export OTEL_EXPORTER_OTLP_ENDPOINT=\"https://enterplace.example.com/otlp\"")
    );
    // Prompt and tool text stay off: the block never turns them on.
    assert!(!out.contains("OTEL_LOG_USER_PROMPTS") && !out.contains("OTEL_LOG_TOOL_DETAILS"));

    for bad in [
        args(&["setup", "--team", "payments"]),
        args(&[
            "setup",
            "--gateway",
            "enterplace.example.com",
            "--team",
            "payments",
        ]),
        args(&["setup", "--gateway", "https://enterplace.example.com"]),
        args(&[
            "setup",
            "--gateway",
            "https://enterplace.example.com",
            "--team",
            "a",
            "--person",
            "b",
        ]),
        args(&[
            "setup",
            "--gateway",
            "https://enterplace.example.com",
            "--team",
            "a",
            "--token",
            "enterplace_dev_x",
        ]),
        args(&["tokens"]),
    ] {
        assert!(super::setup(&bad).is_err(), "{bad:?}");
    }
    Ok(())
}

/// A call with headers of its own: an encoding, or a browser's cookie and origin.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(header::HeaderName, &str)],
    body: Vec<u8>,
) -> Result<Reply, Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    let response = app.clone().oneshot(request.body(Body::from(body))?).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(Reply {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    })
}

fn gzip(plain: &[u8]) -> Result<Vec<u8>, Error> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain)?;
    Ok(encoder.finish()?)
}

/// One model request Claude Code reports, costing `cost`.
fn request_event(sequence: u64, cost: f64) -> Value {
    event(
        "api_request",
        sequence,
        now_ns(),
        vec![
            kv("model", json!("claude-sonnet-5-5")),
            kv("input_tokens", json!(100)),
            kv("output_tokens", json!(10)),
            kv("cost_usd", json!(cost)),
        ],
    )
}

#[tokio::test]
async fn a_gzip_export_is_read_and_one_that_unpacks_too_large_is_refused() -> Result<(), Error> {
    let Some(url) = database("watch_gzip").await? else {
        return Ok(());
    };
    let gw = gateway("watch_gzip", &url, &licensed(&["watch"]))?;
    let (_, token) = new_token(&gw.app, json!({ "label": "team", "team": "payments" })).await?;
    let bearer = format!("Bearer {token}");
    let post = |path: &'static str, kind: &'static str, body: Vec<u8>| {
        let (app, bearer) = (gw.app.clone(), bearer.clone());
        async move {
            let headers = [
                (header::AUTHORIZATION, bearer.as_str()),
                (header::CONTENT_TYPE, kind),
                (header::CONTENT_ENCODING, "gzip"),
            ];
            call(&app, "POST", path, &headers, body).await
        }
    };

    // As Claude Code sends with OTEL_EXPORTER_OTLP_COMPRESSION=gzip: both signals, protobuf and JSON.
    let sent = post("/otlp/v1/metrics", PROTOBUF, gzip(METRICS_PB)?).await?;
    assert_eq!((sent.status, sent.text.as_str()), (StatusCode::OK, ""));
    let sent = post("/otlp/v1/logs", JSON, gzip(LOGS_JSON)?).await?;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    let seen = summary(&gw.app).await?;
    assert_eq!(seen.body["totals"]["tokens_input"], json!(1200.0));
    assert_eq!(seen.body["totals"]["api_requests"], json!(1.0));
    let kept = watch_records(&gw)?.len();
    assert!(kept > 0);

    // A few kilobytes that unpack past the limit: refused as too large, read no further than the limit.
    let bomb = gzip(&vec![b' '; super::MAX_BODY + 1])?;
    assert!(bomb.len() < 64 * 1024, "{}", bomb.len());
    let refused = post("/otlp/v1/logs", JSON, bomb).await?;
    assert_eq!(
        (refused.status, refused.body["error"]["code"].as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large")),
        "{}",
        refused.text
    );
    assert!(refused.text.contains("uncompressed"), "{}", refused.text);
    // Exactly the limit is taken as far as the reader: it is not an export, so it is refused as one.
    let full = post("/otlp/v1/logs", JSON, gzip(&vec![b' '; super::MAX_BODY])?).await?;
    assert_eq!(full.status, StatusCode::BAD_REQUEST, "{}", full.text);

    // Not gzip, and gzip cut short: refused with the fix, nothing kept.
    let cut = gzip(LOGS_PB)?;
    for body in [LOGS_PB.to_vec(), cut[..cut.len() - 9].to_vec()] {
        let refused = post("/otlp/v1/logs", PROTOBUF, body).await?;
        assert_eq!(
            (refused.status, refused.body["error"]["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_export")),
            "{}",
            refused.text
        );
        assert!(
            refused.text.contains("OTEL_EXPORTER_OTLP_COMPRESSION"),
            "{}",
            refused.text
        );
    }
    assert_eq!(watch_records(&gw)?.len(), kept, "nothing refused was kept");
    Ok(())
}

#[tokio::test]
async fn an_email_becomes_the_name_the_install_knows_and_a_stranger_is_listed() -> Result<(), Error>
{
    let Some(url) = database("watch_names").await? else {
        return Ok(());
    };
    let policy = format!(
        "{POLICY}teams:\n  - name: payments\n    owner: lead@acme.co\n    members: [omer@acme.co]\n"
    );
    let gw = gateway_policy(
        "watch_names",
        &url,
        &licensed(&["watch", "members"]),
        &[],
        &policy,
    )?;
    // maya's key says her email; dana's key is named by hers, as single sign-on names keys.
    let mut attributes = enterplace_core::keyfile::Attributes::default();
    attributes
        .options
        .metadata
        .insert("email".into(), "Maya.Cohen@acme.co".into());
    enterplace_core::keyfile::issue_with("maya", "payments", &attributes, &gw.keys)?;
    enterplace_core::keyfile::issue("Dana@acme.co", "payments", &gw.keys)?;
    gw.governed
        .reloader
        .check(enterplace_server::Trigger::FileChange);
    // sam is a member (as an invite or SCIM makes one) without a key.
    let mut owner = Browser::admin(&gw.app).await?;
    let invited = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/invite",
            &[
                ("email", "sam@acme.co"),
                ("role", "viewer"),
                ("team", "ops"),
            ],
        )
        .await?;
    let invite: String = invited
        .text
        .split("/console/invite/")
        .nth(1)
        .ok_or("no invite")?
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    Browser::default()
        .go(
            &gw.app,
            "POST",
            &format!("/console/invite/{invite}"),
            &[("name", "Sam"), ("password", "second-password-123")],
        )
        .await?;

    let (_, token) = new_token(&gw.app, json!({ "label": "team", "team": "payments" })).await?;
    let mut last = Vec::new();
    for (i, email) in [
        "maya.cohen@acme.co",
        "dana@acme.co",
        "omer@acme.co",
        "lead@acme.co",
        "sam@acme.co",
        "stranger@else.co",
    ]
    .iter()
    .enumerate()
    {
        last = logs_body(email, &format!("s-{i}"), vec![request_event(1, 0.5)]);
        let sent = send(&gw.app, "POST", "/otlp/v1/logs", &token, JSON, last.clone()).await?;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    }
    let seen = summary(&gw.app).await?;
    let people: Vec<(&str, bool)> = seen.body["people"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| (p["person"].as_str().unwrap_or_default(), p["known"] == true))
        .collect();
    assert_eq!(
        people,
        [
            ("Dana@acme.co", true),
            ("lead@acme.co", true),
            ("maya", true),
            ("omer@acme.co", true),
            ("sam@acme.co", true),
            ("stranger@else.co", false),
        ],
        "{}",
        seen.text
    );
    assert_eq!(
        seen.body["not_known_members"],
        json!(["stranger@else.co"]),
        "{}",
        seen.text
    );
    assert!(
        seen.body["not_known_members_note"]
            .as_str()
            .is_some_and(|n| n.starts_with("Not a known member")),
        "{}",
        seen.text
    );

    // The record has the name gateway traffic has, and the email Claude Code reported beside it.
    let records = watch_records(&gw)?;
    let of = |session: &str| records.iter().find(|r| r["session"] == session);
    let maya = of("s-0").ok_or("no record of maya")?;
    assert_eq!(
        (&maya["person"], &maya["email"]),
        (&json!("maya"), &json!("maya.cohen@acme.co"))
    );
    let stranger = of("s-5").ok_or("no record of the stranger")?;
    assert_eq!(stranger["person"], "stranger@else.co");
    assert!(stranger.get("email").is_none(), "{stranger}");

    // A key given after an export names the person from then on, and does not make a repeat of that export new.
    let mut attributes = enterplace_core::keyfile::Attributes::default();
    attributes
        .options
        .metadata
        .insert("email".into(), "stranger@else.co".into());
    enterplace_core::keyfile::issue_with("pat", "payments", &attributes, &gw.keys)?;
    gw.governed
        .reloader
        .check(enterplace_server::Trigger::FileChange);
    send(&gw.app, "POST", "/otlp/v1/logs", &token, JSON, last).await?;
    let again = summary(&gw.app).await?;
    assert_eq!(again.body["totals"]["api_requests"], json!(6.0));
    assert_eq!(again.body["not_known_members"], json!([]));

    // One person's token names them whatever Claude Code says: no lookup.
    let (_, own) = new_token(&gw.app, json!({ "label": "one", "person": "noa" })).await?;
    let logs = logs_body("maya.cohen@acme.co", "s-9", vec![request_event(1, 0.5)]);
    send(&gw.app, "POST", "/otlp/v1/logs", &own, JSON, logs).await?;
    let noa = watch_records(&gw)?
        .into_iter()
        .find(|r| r["session"] == "s-9")
        .ok_or("no record of noa")?;
    assert_eq!(noa["person"], "noa");
    Ok(())
}

#[tokio::test]
async fn with_a_chain_per_organization_watch_records_go_to_the_tokens_organization()
-> Result<(), Error> {
    let Some(url) = database("watch_orgs").await? else {
        return Ok(());
    };
    let policy = format!("{POLICY}orgs: [acme, globex]\naudit: {{ per_org: true }}\n");
    let gw = gateway_policy("watch_orgs", &url, &licensed(&["watch"]), &[], &policy)?;

    let refused = admin(
        &gw.app,
        "POST",
        "/console/watch/tokens",
        json!({ "label": "x", "org": "initech" }),
    )
    .await?;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    assert!(refused.text.contains("acme, globex"), "{}", refused.text);

    let (id, acme) = new_token(
        &gw.app,
        json!({ "label": "acme", "team": "payments", "org": "acme" }),
    )
    .await?;
    let (_, install) = new_token(&gw.app, json!({ "label": "install", "team": "ops" })).await?;
    let listed = admin(&gw.app, "GET", "/console/watch/tokens", Value::Null).await?;
    assert_eq!(listed.body["tokens"][0]["org"], "acme", "{}", listed.text);
    assert_eq!(listed.body["tokens"][1]["org"], "", "{}", listed.text);

    for (token, email) in [(&acme, "dana@acme.co"), (&install, "omer@ops.co")] {
        let logs = logs_body(email, "s-1", vec![request_event(1, 0.5)]);
        let sent = send(&gw.app, "POST", "/otlp/v1/logs", token, JSON, logs).await?;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
        let metrics = metrics_body(
            email,
            "s-1",
            vec![sum(
                "claude_code.session.count",
                1,
                now_ns() - 1_000_000_000,
                now_ns(),
                &[(1.0, json!([]))],
            )],
        );
        let sent = send(&gw.app, "POST", "/otlp/v1/metrics", token, JSON, metrics).await?;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    }

    let read = |path: &std::path::Path| -> Result<Vec<Value>, Error> {
        Ok(std::fs::read_to_string(path)?
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|r| r["event"] == "watch")
            .collect())
    };
    gw.log.flush();
    let chain = enterplace_core::audit::org_path(&gw.audit, "acme");
    let of_acme = read(&chain)?;
    assert_eq!(of_acme.len(), 2, "the request and the metrics: {of_acme:?}");
    for record in &of_acme {
        assert_eq!(
            (&record["org"], &record["person"], &record["token"]),
            (&json!("acme"), &json!("dana@acme.co"), &json!(id)),
            "{record}"
        );
    }
    let of_install = read(&gw.audit)?;
    assert_eq!(of_install.len(), 2, "{of_install:?}");
    for record in &of_install {
        assert_eq!(record["person"], "omer@ops.co", "{record}");
        assert!(record.get("org").is_none(), "{record}");
    }
    assert!(enterplace_core::audit::verify(&chain).is_ok());
    assert!(enterplace_core::audit::verify(&gw.audit).is_ok());
    Ok(())
}

#[tokio::test]
async fn a_viewer_lists_watch_tokens_and_only_an_owner_or_admin_issues_and_revokes()
-> Result<(), Error> {
    let Some(url) = database("watch_roles").await? else {
        return Ok(());
    };
    let gw = gateway("watch_roles", &url, &licensed(&["watch", "members"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let mut join = async |role: &str, email: &str| -> Result<Browser, Error> {
        let invited = owner
            .go(
                &gw.app,
                "POST",
                "/console/members/invite",
                &[("email", email), ("role", role), ("team", "ops")],
            )
            .await?;
        let invite: String = invited
            .text
            .split("/console/invite/")
            .nth(1)
            .ok_or("no invite")?
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        let mut person = Browser::default();
        person
            .go(
                &gw.app,
                "POST",
                &format!("/console/invite/{invite}"),
                &[("name", "Sam"), ("password", "second-password-123")],
            )
            .await?;
        Ok(person)
    };
    let viewer = join("viewer", "viewer@example.com").await?;
    let member = join("admin", "admin@example.com").await?;
    let origin = format!("http://{HOST}");
    let as_person = |who: &Browser, method: &'static str, path: String, body: Value| {
        let (app, cookie, origin) = (gw.app.clone(), who.cookie.clone(), origin.clone());
        async move {
            let headers = [
                (header::COOKIE, cookie.as_str()),
                (header::ORIGIN, origin.as_str()),
                (header::CONTENT_TYPE, JSON),
            ];
            let body = if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            };
            call(&app, method, &path, &headers, body).await
        }
    };
    let tokens = "/console/watch/tokens".to_string();
    let (id, token) = new_token(&gw.app, json!({ "label": "team", "team": "payments" })).await?;

    // A viewer reads: the list (never a token itself) and the summary.
    let listed = as_person(&viewer, "GET", tokens.clone(), Value::Null).await?;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    assert_eq!(listed.body["tokens"][0]["id"], json!(id), "{}", listed.text);
    assert!(
        !listed.text.contains("enterplace_watch_"),
        "{}",
        listed.text
    );
    let looked = as_person(
        &viewer,
        "GET",
        "/console/watch/summary.json".into(),
        Value::Null,
    )
    .await?;
    assert_eq!(looked.status, StatusCode::OK, "{}", looked.text);

    // A viewer changes nothing, and each try is recorded with its code.
    let made = as_person(&viewer, "POST", tokens.clone(), json!({ "label": "mine" })).await?;
    assert_eq!(
        (made.status, made.body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("read_only")),
        "{}",
        made.text
    );
    assert!(made.text.contains("Your role is viewer"), "{}", made.text);
    let revoked = as_person(&viewer, "DELETE", format!("{tokens}/{id}"), Value::Null).await?;
    assert_eq!(
        (revoked.status, revoked.body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("read_only")),
        "{}",
        revoked.text
    );
    let still = send(
        &gw.app,
        "POST",
        "/otlp/v1/logs",
        &token,
        PROTOBUF,
        LOGS_PB.to_vec(),
    )
    .await?;
    assert_eq!(
        still.status,
        StatusCode::OK,
        "the token a viewer tried to revoke works"
    );
    // Nobody signed in reads or changes anything.
    let nobody = Browser::default();
    for method in ["GET", "POST"] {
        let refused = as_person(&nobody, method, tokens.clone(), json!({ "label": "x" })).await?;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "{method}: {}",
            refused.text
        );
    }

    // A member with the admin role issues and revokes.
    let made = as_person(
        &member,
        "POST",
        tokens.clone(),
        json!({ "label": "by-admin" }),
    )
    .await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
    let theirs = made.body["id"].as_str().unwrap_or_default().to_string();
    let revoked = as_person(&member, "DELETE", format!("{tokens}/{theirs}"), Value::Null).await?;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.text);
    let listed = as_person(&viewer, "GET", tokens.clone(), Value::Null).await?;
    let status = |of: &str| {
        listed.body["tokens"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|t| t["id"] == of)
            .and_then(|t| t["status"].as_str())
            .map(str::to_string)
    };
    assert_eq!(status(&id).as_deref(), Some("receiving"), "{}", listed.text);
    assert_eq!(
        status(&theirs).as_deref(),
        Some("revoked"),
        "{}",
        listed.text
    );

    gw.log.flush();
    let chain = std::fs::read_to_string(&gw.audit)?;
    let records: Vec<Value> = chain
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let count = |action: &str, code: Option<&str>| {
        records
            .iter()
            .filter(|r| {
                r["event"] == "admin" && r["action"] == action && r["code"].as_str() == code
            })
            .count()
    };
    assert_eq!(
        count("watch_token_created", Some("read_only")),
        1,
        "{chain}"
    );
    assert_eq!(
        count("watch_token_revoked", Some("read_only")),
        1,
        "{chain}"
    );
    assert_eq!(count("watch_token_created", None), 2, "{chain}");
    assert_eq!(count("watch_token_revoked", None), 1, "{chain}");
    Ok(())
}

/// `enterplace watch setup` without `--token`: the token is created over the network, by a gateway that listens.
#[tokio::test(flavor = "multi_thread")]
async fn setup_creates_its_token_through_a_gateway_that_listens() -> Result<(), Error> {
    let Some(url) = database("watch_setup").await? else {
        return Ok(());
    };
    let gw = gateway("watch_setup", &url, &licensed(&["watch"]))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gateway = format!("http://{}", listener.local_addr()?);
    let app = gw.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let run = |list: &[&str], key: Option<&str>| {
        let args: Vec<String> = std::iter::once("setup")
            .chain(list.iter().copied())
            .map(str::to_string)
            .collect();
        let key = key.map(str::to_string);
        tokio::task::spawn_blocking(move || super::setup_with(&args, key))
    };
    let out = run(
        &["--gateway", &gateway, "--team", "payments", "--days", "30"],
        Some(ADMIN_KEY),
    )
    .await??;
    let token = out
        .split("Authorization=Bearer ")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("no token in the settings")?
        .to_string();
    assert!(
        token.starts_with("enterplace_watch_") && token.len() == super::PREFIX.len() + 64,
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "\"OTEL_EXPORTER_OTLP_ENDPOINT\": \"{gateway}/otlp\""
        )),
        "{out}"
    );
    assert!(!out.contains(ADMIN_KEY), "the admin key is not printed");

    // The token is the gateway's: listed with what setup asked for, and an export sent with it over the network
    // is taken.
    let listed = admin(&gw.app, "GET", "/console/watch/tokens", Value::Null).await?;
    let made = &listed.body["tokens"][0];
    assert_eq!(
        (&made["label"], &made["team"], &made["created_by"]),
        (&json!("watch-payments"), &json!("payments"), &json!("noa")),
        "{}",
        listed.text
    );
    let (endpoint, bearer) = (format!("{gateway}/otlp/v1/logs"), format!("Bearer {token}"));
    let status = tokio::task::spawn_blocking(move || {
        ureq::post(&endpoint)
            .set("authorization", &bearer)
            .set("content-type", PROTOBUF)
            .send_bytes(LOGS_PB)
            .map(|r| r.status())
            .map_err(|e| e.to_string())
    })
    .await??;
    assert_eq!(status, 200);
    assert_eq!(summary(&gw.app).await?.body["people"][0]["person"], MAYA);

    // What the gateway refuses, and no gateway at all, are said with the fix.
    let wrong = run(
        &["--gateway", &gateway, "--team", "payments"],
        Some("enterplace_admin_wrong"),
    )
    .await?;
    assert!(wrong.is_err_and(|e| e.contains("answered 401")));
    let long = run(
        &["--gateway", &gateway, "--team", "payments", "--days", "999"],
        Some(ADMIN_KEY),
    )
    .await?;
    assert!(long.is_err_and(|e| e.contains("answered 400") && e.contains("1 to 365 days")));
    let none = run(&["--gateway", &gateway, "--team", "payments"], None).await?;
    assert!(none.is_err_and(|e| e.contains("ENTERPLACE_ADMIN_KEY")));
    let closed = run(
        &["--gateway", "http://127.0.0.1:9", "--team", "payments"],
        Some(ADMIN_KEY),
    )
    .await?;
    assert!(closed.is_err_and(|e| e.contains("could not be reached")));
    Ok(())
}

/// The IDs of the tokens `key`'s holder is shown.
async fn listed_ids(app: &Router, key: &str) -> Result<Vec<String>, Error> {
    let listed = send(app, "GET", "/console/watch/tokens", key, JSON, Vec::new()).await?;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    Ok(listed.body["tokens"]
        .as_array()
        .map(|tokens| {
            tokens
                .iter()
                .filter(|t| t["status"] != "revoked")
                .filter_map(|t| t["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

async fn as_key(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    body: Value,
) -> Result<Reply, Error> {
    let body = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    send(app, method, path, key, JSON, body).await
}

#[tokio::test]
async fn an_admin_kept_to_an_organization_or_to_teams_reaches_only_its_own_watch_tokens()
-> Result<(), Error> {
    let Some(url) = database("watch_confined").await? else {
        return Ok(());
    };
    let policy = format!("{POLICY}{CONFINED}");
    let gw = gateway_policy("watch_confined", &url, &licensed(&["watch"]), &[], &policy)?;
    confined_admins(&gw)?;
    let app = &gw.app;
    let tokens = "/console/watch/tokens";
    let (acme_pay, _) = new_token(
        app,
        json!({ "label": "a", "team": "payments", "org": "acme" }),
    )
    .await?;
    let (acme_web, _) =
        new_token(app, json!({ "label": "b", "team": "web", "org": "acme" })).await?;
    let (globex_pay, _) = new_token(
        app,
        json!({ "label": "c", "team": "payments", "org": "globex" }),
    )
    .await?;
    let (plain_pay, _) = new_token(app, json!({ "label": "d", "team": "payments" })).await?;
    let (plain_web, _) = new_token(app, json!({ "label": "e", "team": "web" })).await?;

    // Kept to organization acme: its tokens alone, to see, make and revoke.
    assert_eq!(
        listed_ids(app, ACME_KEY).await?,
        [acme_pay.clone(), acme_web.clone()]
    );
    let other = as_key(
        app,
        "POST",
        tokens,
        ACME_KEY,
        json!({ "label": "x", "team": "web", "org": "globex" }),
    )
    .await?;
    assert_eq!(other.status, StatusCode::FORBIDDEN, "{}", other.text);
    assert_eq!(other.body["error"]["code"], "other_org", "{}", other.text);
    let own = as_key(
        app,
        "POST",
        tokens,
        ACME_KEY,
        json!({ "label": "x", "team": "web" }),
    )
    .await?;
    assert_eq!(own.status, StatusCode::CREATED, "{}", own.text);
    let own = own.body["id"].as_str().unwrap_or_default().to_string();
    for outside in [&globex_pay, &plain_pay] {
        let gone = as_key(
            app,
            "DELETE",
            &format!("{tokens}/{outside}"),
            ACME_KEY,
            Value::Null,
        )
        .await?;
        assert_eq!(gone.status, StatusCode::NOT_FOUND, "{}", gone.text);
    }
    let gone = as_key(
        app,
        "DELETE",
        &format!("{tokens}/{acme_web}"),
        ACME_KEY,
        Value::Null,
    )
    .await?;
    assert_eq!(gone.status, StatusCode::OK, "{}", gone.text);

    // Kept to team payments: that team's tokens alone, in any organization.
    assert_eq!(
        listed_ids(app, PAYMENTS_KEY).await?,
        [acme_pay.clone(), globex_pay.clone(), plain_pay.clone()]
    );
    // Signed in to the console with the same key, the same reach.
    let mut browser = Browser::default();
    browser
        .go(app, "POST", "/console/sign-in", &[("key", PAYMENTS_KEY)])
        .await?;
    let seen = browser.go(app, "GET", tokens, &[]).await?;
    assert_eq!(seen.status, StatusCode::OK, "{}", seen.text);
    assert!(
        seen.text.contains(&plain_pay)
            && !seen.text.contains(&plain_web)
            && !seen.text.contains(&acme_web),
        "{}",
        seen.text
    );
    for body in [
        json!({ "label": "x", "team": "web" }),
        // No team is every team, which is more than the role reaches.
        json!({ "label": "x", "person": "dana@acme.co" }),
    ] {
        let refused = as_key(app, "POST", tokens, PAYMENTS_KEY, body).await?;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text);
        assert_eq!(
            refused.body["error"]["code"], "outside_role",
            "{}",
            refused.text
        );
        assert!(refused.text.contains("teams payments"), "{}", refused.text);
    }
    let made = as_key(
        app,
        "POST",
        tokens,
        PAYMENTS_KEY,
        json!({ "label": "x", "team": "payments" }),
    )
    .await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
    let made = made.body["id"].as_str().unwrap_or_default().to_string();
    let gone = as_key(
        app,
        "DELETE",
        &format!("{tokens}/{plain_web}"),
        PAYMENTS_KEY,
        Value::Null,
    )
    .await?;
    assert_eq!(gone.status, StatusCode::NOT_FOUND, "{}", gone.text);
    let gone = as_key(
        app,
        "DELETE",
        &format!("{tokens}/{plain_pay}"),
        PAYMENTS_KEY,
        Value::Null,
    )
    .await?;
    assert_eq!(gone.status, StatusCode::OK, "{}", gone.text);

    // What neither could reach still works, and the refused attempts are in the audit log as refusals.
    assert_eq!(
        listed_ids(app, ADMIN_KEY).await?,
        [acme_pay, globex_pay, plain_web, own, made]
    );
    gw.log.flush();
    let log = std::fs::read_to_string(&gw.audit)?;
    assert!(
        log.contains("outside_role") && log.contains("other_org"),
        "{log}"
    );
    Ok(())
}

#[tokio::test]
async fn an_admin_kept_to_an_organization_or_to_teams_sees_only_its_own_people_in_the_summary()
-> Result<(), Error> {
    let Some(url) = database("watch_confined_summary").await? else {
        return Ok(());
    };
    let policy = format!("{POLICY}{CONFINED}");
    let gw = gateway_policy(
        "watch_confined_summary",
        &url,
        &licensed(&["watch"]),
        &[],
        &policy,
    )?;
    confined_admins(&gw)?;
    let app = &gw.app;
    for (body, email, cost) in [
        (
            json!({ "label": "a", "team": "payments", "org": "acme" }),
            "dana@acme.co",
            1.0,
        ),
        (
            json!({ "label": "b", "team": "payments", "org": "globex" }),
            "gil@globex.co",
            2.0,
        ),
        (json!({ "label": "c", "team": "web" }), "omer@ops.co", 4.0),
    ] {
        let (_, token) = new_token(app, body).await?;
        let (start, now) = (now_ns() - 1_000_000_000, now_ns());
        let cost = sum(
            "claude_code.cost.usage",
            1,
            start,
            now,
            &[(cost, json!([]))],
        );
        let metrics = metrics_body(email, "s-1", vec![cost]);
        let sent = send(app, "POST", "/otlp/v1/metrics", &token, JSON, metrics).await?;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    }
    let seen = async |key: &str| -> Result<(Vec<String>, f64, String), Error> {
        let reply = as_key(app, "GET", "/console/watch/summary.json", key, Value::Null).await?;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let people = reply.body["people"]
            .as_array()
            .map(|people| {
                people
                    .iter()
                    .filter_map(|p| p["person"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let cost = reply.body["totals"]["cost_usd"].as_f64().unwrap_or(0.0);
        Ok((people, cost, reply.text))
    };
    let (people, cost, _) = seen(ADMIN_KEY).await?;
    assert_eq!(people, ["dana@acme.co", "gil@globex.co", "omer@ops.co"]);
    assert_eq!(cost, 7.0);
    // Kept to organization acme: its people and their sums alone, in every list of the summary.
    let (people, cost, text) = seen(ACME_KEY).await?;
    assert_eq!(people, ["dana@acme.co"], "{text}");
    assert_eq!(cost, 1.0, "{text}");
    assert!(!text.contains("gil@") && !text.contains("omer@"), "{text}");
    // Kept to team payments: that team in any organization.
    let (people, cost, text) = seen(PAYMENTS_KEY).await?;
    assert_eq!(people, ["dana@acme.co", "gil@globex.co"], "{text}");
    assert_eq!(cost, 3.0, "{text}");
    assert!(!text.contains("omer@"), "{text}");
    Ok(())
}
