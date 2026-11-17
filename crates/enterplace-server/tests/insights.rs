//! What the request log reads from the audit log: the coding agent and latency of each request, an upstream error
//! for a request no provider answered, and the sealed, redacted body of a rule with `capture:`.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789ab";
const MASTER: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// A provider that answers with an email address in the text, whole or streamed.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move {
            let stream = body.windows(13).any(|w| w == b"\"stream\":true");
            let (content_type, text) = if stream {
                (
                    "text/event-stream",
                    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"write to dana@example.com\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\ndata: [DONE]\n\n",
                )
            } else {
                (
                    "application/json",
                    r#"{"id":"c1","choices":[{"message":{"role":"assistant","content":"write to dana@example.com"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#,
                )
            };
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(text))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16, dead: u16, capture: bool) -> String {
    let capture = if capture {
        "    capture: { to: console, days: 7, viewers: [noa.bar, \"team:security\"] }\n"
    } else {
        ""
    };
    format!(
        "version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [gpt-4o-mini]
  - name: gone
    kind: openai
    url: http://127.0.0.1:{dead}
    allow_private: true
    key_env: MOCK_KEY
    models: [gone-model]
rules:
  - name: payments
    principals: {{ team: payments }}
    models: [gpt-4o-mini, gone-model]
{capture}"
    )
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir =
        std::env::temp_dir().join(format!("enterplace-insights-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    Ok(dir)
}

fn env(master: bool) -> impl Fn(&str) -> Option<String> {
    move |name: &str| match name {
        "ENTERPLACE_MASTER_KEY" => master.then(|| MASTER.to_string()),
        "ENTERPLACE_MASTER_KEY_FILE" => None,
        _ => Some("provider-secret".into()),
    }
}

fn chat(body: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::USER_AGENT, "claude-cli/2.0.1 (external, cli)")
        .body(Body::from(body.to_string()))
}

async fn send(app: &Router, request: Request<Body>) -> Result<(StatusCode, String, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let id = response
        .headers()
        .get("x-enterplace-decision")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, id, String::from_utf8_lossy(&body).into_owned()))
}

/// The record of `event` for decision `id`, waiting for it: usage is written when the answer ends.
async fn record(audit: &Path, event: Option<&str>, id: &str) -> Result<Value, Error> {
    let start = Instant::now();
    loop {
        let found = std::fs::read_to_string(audit)?
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|r| r["id"] == id && r["event"].as_str() == event);
        if let Some(found) = found {
            return Ok(found);
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err(format!("no {event:?} record for {id}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn records_carry_the_agent_and_latency_and_a_failed_upstream_is_an_error() -> TestResult {
    let port = provider().await?;
    let dead = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        l.local_addr()?.port()
    };
    let dir = dir("records")?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, self::policy(port, dead, false))?;
    let gw = enterplace_server::governed(&policy, None, &env(false))?;
    let audit = dir.join("enterplace-audit.jsonl");

    let (status, id, _) = send(
        &gw.router,
        chat(r#"{"model":"gpt-4o-mini","messages":[]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let decision = record(&audit, None, &id).await?;
    assert_eq!(decision["user_agent"], "claude-cli/2.0.1 (external, cli)");
    let usage = record(&audit, Some("usage"), &id).await?;
    assert!(usage["latency_ms"].as_u64().is_some(), "{usage}");
    assert!(
        usage.get("body").is_none(),
        "nothing is captured without capture:"
    );

    let (status, id, _) =
        send(&gw.router, chat(r#"{"model":"gone-model","messages":[]}"#)?).await?;
    assert!(status.is_server_error(), "{status}");
    let failed = record(&audit, Some("upstream_error"), &id).await?;
    assert_eq!(failed["status"], status.as_u16());
    assert!(
        failed["code"]
            .as_str()
            .is_some_and(|c| c.starts_with("upstream_")),
        "{failed}"
    );
    // A failure that was not retried still names its provider, so provider_errors alerts count it.
    assert_eq!(failed["provider"], "gone", "{failed}");
    assert_eq!(failed["tries"], 1, "{failed}");
    gw.log.flush();
    let rows = enterplace_core::insights::fold_chain(&audit)?;
    let row = rows.iter().find(|r| r.id == id).ok_or("no row")?;
    assert_eq!(row.outcome(), enterplace_core::insights::Outcome::Error);
    Ok(())
}

#[tokio::test]
async fn capture_needs_the_master_key_and_keeps_bodies_redacted_and_sealed() -> TestResult {
    let port = provider().await?;
    let dir = dir("capture")?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, self::policy(port, 1, true))?;

    let refused = enterplace_server::governed(&policy, None, &env(false))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        refused.contains("rule \"payments\" has capture:")
            && refused.contains("ENTERPLACE_MASTER_KEY"),
        "{refused}"
    );

    let gw = enterplace_server::governed(&policy, None, &env(true))?;
    let audit = dir.join("enterplace-audit.jsonl");
    let mut ids = Vec::new();
    for stream in [false, true] {
        let body = format!(
            r#"{{"model":"gpt-4o-mini","stream":{stream},"messages":[{{"role":"user","content":"my key is AKIAIOSFODNN7EXAMPLE"}}]}}"#
        );
        let (status, id, _) = send(&gw.router, chat(&body)?).await?;
        assert_eq!(status, StatusCode::OK);
        let usage = record(&audit, Some("usage"), &id).await?;
        assert_eq!(usage["body"], "captured", "{usage}");
        ids.push(id);
    }
    let bodies = enterplace_core::insights::attached(&audit)
        .bodies
        .ok_or("no body store")?;
    for id in &ids {
        let start = Instant::now();
        let body = loop {
            if let Some(body) = bodies.body(id).await? {
                break body;
            }
            if start.elapsed() > Duration::from_secs(3) {
                return Err(format!("no body kept for {id}").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(
            body.request.contains("[MASKED aws_access_key]"),
            "{}",
            body.request
        );
        assert!(!body.request.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(
            body.answer.contains("[MASKED email_address]"),
            "{}",
            body.answer
        );
        assert!(!body.answer.contains("dana@example.com"));
        assert_eq!(body.rule, "payments");
        assert_eq!(body.viewers, ["noa.bar", "team:security"]);
        assert!(body.expires > enterplace_core::insights::now_secs() + 6 * 86_400);
    }
    // On disk the body is sealed: not even the redacted text can be read without the master key.
    let mut on_disk = Vec::new();
    for day in std::fs::read_dir(enterplace_core::insights::bodies_dir(&audit))? {
        for file in std::fs::read_dir(day?.path())? {
            on_disk.extend(std::fs::read(file?.path())?);
        }
    }
    let text = String::from_utf8_lossy(&on_disk);
    assert!(!on_disk.is_empty() && !text.contains("MASKED") && !text.contains("payments"));
    Ok(())
}

/// A fresh database on the server ENTERPLACE_TEST_DATABASE_URL names, as a connection string. `None` when it is not set.
async fn database(test: &str) -> Result<Option<enterplace_server::store::TestDatabase>, Error> {
    enterplace_server::store::TestDatabase::create(&format!(
        "enterplace_{}_{test}",
        std::process::id()
    ))
    .await
}

fn decision(id: &str, team: &str, allowed: bool) -> serde_json::Map<String, Value> {
    let mut r = enterplace_core::audit::record(&enterplace_core::audit::Entry {
        id,
        person: Some("maya.cohen"),
        team: Some(team),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("gpt-4o-mini"),
        allowed,
        code: (!allowed).then_some("model_not_allowed"),
        provider: if allowed { "openai" } else { "" },
        ..enterplace_core::audit::Entry::default()
    });
    r.insert("user_agent".into(), "codex_cli_rs/0.1".into());
    r
}

fn object(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

#[tokio::test]
async fn the_index_holds_every_replica_and_answers_as_the_local_chain_does() -> TestResult {
    let Some(url) = database("insights_index").await? else {
        return Ok(());
    };
    use enterplace_core::insights::{Bodies, Index, Query};
    let pg = enterplace_server::store::open("ENTERPLACE_TEST_DATABASE_URL", &url)?;
    let master = enterplace_server::MasterKey::from_env(&|n: &str| {
        (n == "ENTERPLACE_MASTER_KEY").then(|| MASTER.to_string())
    })?
    .ok_or("no master key")?;
    let seal: std::sync::Arc<dyn enterplace_core::insights::Seal> =
        std::sync::Arc::new(enterplace_server::insights::Sealer(master));
    let mut replicas = Vec::new();
    for (name, team) in [("a", "payments"), ("b", "search")] {
        let dir = dir(&format!("index-{name}"))?;
        let path = dir.join("enterplace-audit.jsonl");
        let log = enterplace_core::audit::AuditLog::open(&path)?;
        let id = |n: u32| format!("01{}{n:023}", name.to_uppercase());
        log.append_record(&decision(&id(1), team, true))?;
        log.append_record(&decision(&id(2), team, false))?;
        log.append_record(&object(serde_json::json!({"event": "usage", "id": id(1), "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 10, "output_tokens": 5, "cost_usd": 0.5, "charged_usd": 0.5, "latency_ms": 1200})))?;
        log.flush();
        let index = enterplace_server::insights::PgIndex::open(
            pg.clone(),
            &path,
            Some(seal.clone()),
            false,
        )?;
        assert_eq!(index.copy().await?, 3);
        // Written after the first pass: the next one picks up from the cursor and fills in the row.
        log.append_record(&decision(&id(3), team, true))?;
        log.append_record(&object(serde_json::json!({"event": "upstream_error", "id": id(3), "status": 504, "code": "upstream_timeout", "latency_ms": 30000})))?;
        log.flush();
        assert_eq!(index.copy().await?, 2);
        assert_eq!(index.copy().await?, 0, "nothing new");
        // How far it has copied, for whatever removes records from the disk: the chain's last record.
        let last = std::fs::read_to_string(&path)?
            .lines()
            .last()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|record| record["n"].as_u64())
            .ok_or("no last record")?;
        assert_eq!(
            index.copied().load(std::sync::atomic::Ordering::SeqCst),
            last
        );
        replicas.push((index, path));
    }
    assert_ne!(replicas[0].0.replica(), replicas[1].0.replica());

    // What a budget forecast reads: the charged spend of a window, summed in SQL by team over every replica.
    let since = |from: &str| Query {
        from: from.to_string(),
        ..Query::default()
    };
    let mut spent = replicas[0].0.spent(&since("2000-01-01"), "team").await?;
    spent.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        spent,
        vec![("payments".to_string(), 0.5), ("search".to_string(), 0.5)]
    );
    assert!(
        replicas[0]
            .0
            .spent(&since("2999-01-01"), "team")
            .await?
            .is_empty(),
        "nothing after the window starts"
    );

    // Every replica's rows, folded locally, in the index's order.
    let mut local = Vec::new();
    for (index, path) in &replicas {
        let reader = enterplace_core::audit::chain_reader(path)?;
        local.extend(enterplace_core::insights::fold(reader, index.replica()));
    }
    local.sort_by(|a, b| b.time.cmp(&a.time).then(b.id.cmp(&a.id)));
    let index = &replicas[0].0;
    let fields: [&[(&str, &str)]; 6] = [
        &[],
        &[("team", "search")],
        &[("outcome", "error")],
        &[("outcome", "refused"), ("code", "model_not_allowed")],
        &[("min_cost", "0.1"), ("agent", "codex")],
        &[("min_ms", "2000")],
    ];
    for pairs in fields {
        let mut query = Query::parse(&|name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map_or(String::new(), |(_, v)| (*v).to_string())
        })?;
        query.limit = 100;
        let from_index = index.rows(&query).await?;
        let expected = query.select(&local);
        assert!(!expected.is_empty(), "{pairs:?} matches something");
        assert_eq!(from_index, expected, "{pairs:?}");
        assert!(from_index.iter().all(|r| r.checks_out() && r.linked));
    }
    // The reach of a role kept to teams: any of them, as the local fold reads it; a dimension Enterplace does not define
    // matches nothing.
    for (dimension, teams, some) in [
        ("team", vec!["search".to_string(), "nope".to_string()], true),
        (
            "team",
            vec!["payments".to_string(), "search".to_string()],
            true,
        ),
        ("team", vec!["nope".to_string()], false),
        ("not_a_dimension", vec!["search".to_string()], false),
    ] {
        let query = Query {
            within: vec![(dimension.to_string(), teams.clone())],
            limit: 100,
            ..Query::default()
        };
        let from_index = index.rows(&query).await?;
        assert_eq!(from_index, query.select(&local), "{dimension} {teams:?}");
        assert_eq!(!from_index.is_empty(), some, "{dimension} {teams:?}");
    }

    // Bodies: sealed in the table, opened for a reader, gone when expired.
    let now = enterplace_core::insights::now_secs();
    let body = enterplace_core::insights::Body {
        id: "01BODY".into(),
        time: enterplace_core::audit::timestamp(),
        rule: "payments".into(),
        expires: now + 3600,
        viewers: vec!["noa.bar".into()],
        request: "[MASKED email_address]".into(),
        answer: "ok".into(),
    };
    index.keep(body.clone());
    index.keep(enterplace_core::insights::Body {
        id: "01GONE".into(),
        expires: now.saturating_sub(10),
        ..body.clone()
    });
    index.copy().await?;
    assert_eq!(index.body("01BODY").await?, Some(body));
    assert_eq!(index.body("01GONE").await?, None);
    let client = pg.connect().await?;
    let left: i64 = client
        .query_one("SELECT count(*) FROM enterplace_bodies WHERE position(CAST('MASKED' AS bytea) in sealed) > 0", &[])
        .await?
        .try_get(0)?;
    assert_eq!(left, 0, "no body text is readable in the table");
    let all: i64 = client
        .query_one("SELECT count(*) FROM enterplace_bodies", &[])
        .await?
        .try_get(0)?;
    assert_eq!(all, 1, "the expired body was deleted");
    Ok(())
}

#[tokio::test]
async fn legal_hold_keeps_expired_bodies_and_retention_takes_rows_and_bodies_with_the_records()
-> TestResult {
    let Some(url) = database("insights_retention").await? else {
        return Ok(());
    };
    use enterplace_core::insights::{Bodies, Index, Query};
    let pg = enterplace_server::store::open("ENTERPLACE_TEST_DATABASE_URL", &url)?;
    let master = enterplace_server::MasterKey::from_env(&|n: &str| {
        (n == "ENTERPLACE_MASTER_KEY").then(|| MASTER.to_string())
    })?
    .ok_or("no master key")?;
    let seal: std::sync::Arc<dyn enterplace_core::insights::Seal> =
        std::sync::Arc::new(enterplace_server::insights::Sealer(master));
    let dir = dir("index-retention")?;
    let path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&path)?;
    let id = |n: u32| format!("01R{n:024}");
    for n in 1..=3 {
        log.append_record(&decision(&id(n), "payments", true))?;
    }
    log.flush();
    let index = enterplace_server::insights::PgIndex::open(pg.clone(), &path, Some(seal), false)?;
    let now = enterplace_core::insights::now_secs();
    let body = |n: u32, expires: u64| enterplace_core::insights::Body {
        id: id(n),
        time: enterplace_core::audit::timestamp(),
        rule: "payments".into(),
        expires,
        viewers: vec!["noa.bar".into()],
        request: "[MASKED email_address]".into(),
        answer: "ok".into(),
    };
    index.keep(body(1, now + 3600));
    index.keep(body(3, now.saturating_sub(10)));
    let count = |table: &'static str| {
        let pg = pg.clone();
        async move {
            let client = pg.connect().await?;
            let n: i64 = client
                .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await?
                .try_get(0)?;
            Ok::<i64, Error>(n)
        }
    };
    // Under legal hold an expired body is kept.
    enterplace_core::insights::hold(&path, true);
    index.copy().await?;
    assert_eq!(
        count("enterplace_bodies").await?,
        2,
        "a held body was deleted"
    );
    assert_eq!(count("enterplace_requests").await?, 3);
    enterplace_core::insights::hold(&path, false);
    index.copy().await?;
    assert_eq!(
        count("enterplace_bodies").await?,
        1,
        "the expired body stays after the hold"
    );
    // Segments kept elsewhere leave the disk with their rows kept.
    log.append_record(&object(serde_json::json!({"event": "audit_retired", "from_n": 1, "through_n": 2, "kept": "s3://audit/enterplace"})))?;
    log.flush();
    index.copy().await?;
    assert_eq!(count("enterplace_requests").await?, 3);
    // Retention removes records 1 and 2 from the chain: their rows and the body of 1 go with them.
    log.append_record(&object(
        serde_json::json!({"event": "audit_retired", "from_n": 1, "through_n": 2}),
    ))?;
    log.flush();
    index.copy().await?;
    let mut query = Query::parse(&|_: &str| String::new())?;
    query.limit = 100;
    let left: Vec<String> = index
        .rows(&query)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(left, vec![id(3)]);
    assert_eq!(index.body(&id(1)).await?, None);
    assert_eq!(count("enterplace_bodies").await?, 0);
    Ok(())
}

#[tokio::test]
async fn analytics_summed_in_the_store_match_the_local_fold() -> TestResult {
    let Some(url) = database("insights_analytics").await? else {
        return Ok(());
    };
    use enterplace_core::insights::{Index, Query};
    let pg = enterplace_server::store::open("ENTERPLACE_TEST_DATABASE_URL", &url)?;
    let dir = dir("index-analytics")?;
    let path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&path)?;
    for n in 1..=9u32 {
        let id = format!("01A{n:024}");
        let team = if n % 3 == 0 { "search" } else { "payments" };
        log.append_record(&decision(&id, team, n != 5))?;
        if n != 5 {
            log.append_record(&object(serde_json::json!({"event": "usage", "id": id, "provider": "openai", "model": "gpt-4o-mini", "status": if n == 7 { 500 } else { 200 }, "input_tokens": n, "output_tokens": 2, "cost_usd": f64::from(n) / 10.0, "charged_usd": 0.1, "latency_ms": n * 100})))?;
        }
    }
    log.flush();
    let index = enterplace_server::insights::PgIndex::open(pg, &path, None, false)?;
    index.copy().await?;
    let mut query = Query::parse(&|_: &str| String::new())?;
    query.limit = enterplace_core::insights::MAX_ROWS;
    let reader = enterplace_core::audit::chain_reader(&path)?;
    let local = enterplace_core::insights::fold(reader, index.replica());
    for (hourly, dimension) in [(true, "team"), (false, "model"), (false, "customer")] {
        let expected =
            enterplace_core::insights::analytics(&query.select(&local), hourly, dimension);
        let summed = index.analytics(&query, hourly, dimension).await?;
        let same = |a: &enterplace_core::insights::Stats, b: &enterplace_core::insights::Stats| {
            (
                a.requests,
                a.refused,
                a.errors,
                a.input_tokens,
                a.output_tokens,
            ) == (
                b.requests,
                b.refused,
                b.errors,
                b.input_tokens,
                b.output_tokens,
            ) && (a.cost_usd - b.cost_usd).abs() < 1e-9
                && [50.0, 95.0, 99.0]
                    .iter()
                    .all(|p| a.percentile(*p) == b.percentile(*p))
        };
        assert!(
            same(&summed.totals, &expected.totals),
            "{summed:?} {expected:?}"
        );
        assert_eq!(summed.series.len(), expected.series.len());
        for ((k1, a), (k2, b)) in summed.series.iter().zip(&expected.series) {
            assert!(k1 == k2 && same(a, b), "{k1} {a:?} {k2} {b:?}");
        }
        assert_eq!(summed.ranking.len(), expected.ranking.len(), "{dimension}");
        for ((k1, a), (k2, b)) in summed.ranking.iter().zip(&expected.ranking) {
            assert!(k1 == k2 && same(a, b), "{dimension}: {k1} {a:?} {k2} {b:?}");
        }
    }
    Ok(())
}
