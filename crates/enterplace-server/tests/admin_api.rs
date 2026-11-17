//! The admin API as one table: the OpenAPI document at `/admin/openapi.json` lists every route the gateway serves and
//! no other, each with the action its admin record carries; `/admin/usage` sums spend, tokens and requests by any
//! dimension, day or hour, as JSON or CSV, within the caller's organization; and the policy can be managed a part at a
//! time (providers, models and prices, rules, guardrails, MCP servers, aliases, budgets), each change a new policy
//! version recorded in the audit chain.
//!
//! The policy version tests need ENTERPLACE_TEST_DATABASE_URL, as the store tests do; without it they say they were
//! skipped and pass.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const ROOT: &str = "enterplace_root_0123456789abcdef0123456789ab";
const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789ab";
const DANA: &str = "enterplace_dana_0123456789abcdef0123456789ab";
const FIN: &str = "enterplace_fin_0123456789abcdef0123456789abc";
const LOOK: &str = "enterplace_look_0123456789abcdef0123456789ab";

/// A provider that answers every chat with 10 input and 5 output tokens.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"id":"c","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#,
                ))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16, store: &str) -> String {
    format!(
        "version: 1
{store}providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [m, n]
prices:
  m: {{ input: 1, output: 2 }}
  n: {{ input: 1, output: 2 }}
orgs: [acme, globex]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m, n]
roles:
  - name: finance
    permissions: [see_spend]
    org: acme
  - name: looker
    permissions: [see_keys]
"
    )
}

fn keys() -> String {
    let entry = |name: &str, team: &str, key: &str, extra: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n{extra}",
            sha256_hex(key.as_bytes())
        )
    };
    format!(
        "keys:\n{}{}{}{}{}",
        entry("root", "ops", ROOT, "    admin: true\n"),
        entry("maya.cohen", "payments", MAYA, "    org: acme\n"),
        entry("dana.levi", "search", DANA, "    org: globex\n"),
        entry("fin", "money", FIN, "    org: acme\n    role: finance\n"),
        entry("look", "ops", LOOK, "    role: looker\n"),
    )
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir =
        std::env::temp_dir().join(format!("enterplace-adminapi-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.keys.yaml"), keys())?;
    Ok(dir)
}

fn gateway(
    dir: &Path,
    text: &str,
    store: Option<String>,
) -> Result<enterplace_server::Governed, String> {
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, text).map_err(|e| e.to_string())?;
    enterplace_server::governed(&policy, None, &move |variable| match variable {
        "ENTERPLACE_STORE_URL" => store.clone(),
        "MOCK_KEY" => Some("provider-secret".into()),
        _ => None,
    })
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: &str,
) -> Result<(StatusCode, String, String, String), Error> {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(key) = key {
        request = request.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let (decision, kind) = (header("x-enterplace-decision"), header("content-type"));
    let body = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        decision,
        kind,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::String(text.to_string()))
}

/// The admin record of decision `id`.
fn admin_record(audit: &Path, id: &str) -> Result<Value, Error> {
    std::fs::read_to_string(audit)?
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|r| r["id"] == id && r["event"] == "admin")
        .ok_or_else(|| format!("no admin record for {id}").into())
}

fn fits(template: &str, path: &str) -> bool {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    t.len() == p.len()
        && t.iter()
            .zip(&p)
            .all(|(t, p)| t == p || (t.starts_with('{') && !p.is_empty()))
}

#[tokio::test]
async fn the_openapi_document_lists_every_admin_route_and_no_other() -> TestResult {
    let port = provider().await?;
    let dir = dir("openapi")?;
    let gw = gateway(&dir, &policy(port, ""), None)?;
    let audit = dir.join("enterplace-audit.jsonl");

    // The document needs no key.
    let (status, _, kind, body) = call(&gw.router, "GET", "/admin/openapi.json", None, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(kind.starts_with("application/json"));
    let doc = json(&body);
    assert_eq!(doc["openapi"], "3.1.0");
    let paths = doc["paths"].as_object().ok_or("no paths")?;
    let mut documented = Vec::new();
    for (template, methods) in paths {
        for (method, operation) in methods.as_object().ok_or("no methods")? {
            documented.push((
                template.clone(),
                method.to_ascii_uppercase(),
                operation["operationId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            ));
        }
    }
    for route in [
        "/admin/usage",
        "/admin/teams",
        "/admin/models",
        "/admin/budgets",
        "/admin/providers/{name}",
        "/admin/rules/{name}",
        "/admin/guardrails/{name}",
        "/admin/mcp/{name}",
        "/admin/aliases/{name}",
        "/admin/kills",
        "/admin/credentials/{name}",
        "/admin/policy/versions/{n}/rollback",
    ] {
        assert!(paths.contains_key(route), "{route} is not documented");
    }
    // A method the document does not give a path, and a path it does not hold, are refused and recorded.
    for (template, _, _) in &documented {
        let path = template
            .replace("{prefix}", "1a2b3c4d")
            .replace("{name}", "nope")
            .replace("{n}", "1")
            .replace("{model}", "m");
        let Some(method) = ["GET", "POST", "PUT", "PATCH", "DELETE"]
            .into_iter()
            .find(|m| {
                !documented
                    .iter()
                    .any(|(t, dm, _)| dm == m && fits(t, &path))
            })
        else {
            continue;
        };
        let (status, decision, _, body2) = call(&gw.router, method, &path, Some(ROOT), "").await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {body2}");
        assert_eq!(
            json(&body2)["error"]["code"],
            "unknown_route",
            "{method} {path}"
        );
        gw.log.flush();
        assert_eq!(admin_record(&audit, &decision)?["code"], "unknown_route");
    }
    let (status, _, _, body) =
        call(&gw.router, "GET", "/admin/nothing-here", Some(ROOT), "").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"]["code"], "unknown_route");
    // Every documented route is served by the module that writes the action the document names. The admin key
    // revokes itself last.
    documented.sort_by_key(|(_, _, action)| action == "revoke_own_key");
    for (template, method, action) in &documented {
        if action == "openapi" {
            continue;
        }
        let path = template
            .replace("{prefix}", "1a2b3c4d")
            .replace("{name}", "nope")
            .replace("{n}", "1")
            .replace("{model}", "m");
        let (status, decision, _, body) = call(&gw.router, method, &path, Some(ROOT), "{}").await?;
        gw.log.flush();
        let record = admin_record(&audit, &decision)?;
        assert_eq!(
            record["action"],
            action.as_str(),
            "{method} {path} answered {status} {body}"
        );
        assert_ne!(
            json(&body)["error"]["code"],
            "unknown_route",
            "{method} {path}"
        );
    }
    Ok(())
}

async fn chat(app: &Router, key: &str, model: &str) -> TestResult {
    let (status, _, _, body) = call(
        app,
        "POST",
        "/v1/chat/completions",
        Some(key),
        &json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}).to_string(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// Waits for the usage records of `n` requests: they are written when an answer ends.
async fn usage_records(audit: &Path, n: usize) -> TestResult {
    let start = Instant::now();
    loop {
        let found = std::fs::read_to_string(audit)?
            .lines()
            .filter(|l| l.contains("\"event\":\"usage\""))
            .count();
        if found >= n {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err(format!("{found} usage records, not {n}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn usage_sums_spend_tokens_and_requests_by_any_dimension_as_json_and_csv() -> TestResult {
    let port = provider().await?;
    let dir = dir("usage")?;
    let gw = gateway(&dir, &policy(port, ""), None)?;
    let audit = dir.join("enterplace-audit.jsonl");
    chat(&gw.router, MAYA, "m").await?;
    chat(&gw.router, MAYA, "n").await?;
    chat(&gw.router, DANA, "m").await?;
    usage_records(&audit, 3).await?;
    gw.log.flush();

    let (status, decision, _, body) = call(
        &gw.router,
        "GET",
        "/admin/usage?group_by=team",
        Some(ROOT),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let usage = json(&body);
    assert_eq!(usage["group_by"], "team");
    assert_eq!(usage["counted_by"], "this gateway");
    assert_eq!(usage["totals"]["requests"], 3);
    assert_eq!(usage["totals"]["input_tokens"], 30);
    assert_eq!(usage["totals"]["output_tokens"], 15);
    let groups = usage["groups"].as_array().ok_or("no groups")?;
    let payments = groups
        .iter()
        .find(|g| g["team"] == "payments")
        .ok_or("no payments")?;
    assert_eq!(payments["requests"], 2);
    assert_eq!(payments["total_tokens"], 30);
    // 10 input tokens at $1 and 5 output at $2 a million, twice.
    let spend = payments["spend_usd"].as_f64().unwrap_or_default();
    assert!((spend - 0.00004).abs() < 1e-9, "{spend}");
    gw.log.flush();
    let record = admin_record(&audit, &decision)?;
    assert_eq!(record["action"], "usage");

    for (group, value, requests) in [
        ("model", "n", 1),
        ("person", "dana.levi", 1),
        ("org", "acme", 2),
        ("provider", "mock", 3),
    ] {
        let (status, _, _, body) = call(
            &gw.router,
            "GET",
            &format!("/admin/usage?group_by={group}"),
            Some(ROOT),
            "",
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let usage = json(&body);
        let row = usage["groups"]
            .as_array()
            .and_then(|g| g.iter().find(|r| r[group] == value).cloned())
            .ok_or(format!("no {group} {value} in {usage}"))?;
        assert_eq!(row["requests"], requests, "{group}");
    }
    // By day and by hour, filtered by a dimension and a time range.
    let today = &enterplace_core::audit::timestamp()[..10];
    let (_, _, _, body) = call(
        &gw.router,
        "GET",
        &format!("/admin/usage?group_by=day&team=payments&from={today}&to={today}"),
        Some(ROOT),
        "",
    )
    .await?;
    let usage = json(&body);
    assert_eq!(usage["groups"][0]["day"], today, "{usage}");
    assert_eq!(usage["groups"][0]["requests"], 2);
    let (_, _, _, body) = call(
        &gw.router,
        "GET",
        "/admin/usage?group_by=hour&from=2001-01-01&to=2001-01-02",
        Some(ROOT),
        "",
    )
    .await?;
    assert_eq!(json(&body)["totals"]["requests"], 0);

    // CSV, by the format parameter.
    let (status, _, kind, csv) = call(
        &gw.router,
        "GET",
        "/admin/usage?group_by=model&format=csv",
        Some(ROOT),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(kind.starts_with("text/csv"), "{kind}");
    let mut lines = csv.lines();
    assert_eq!(
        lines.next(),
        Some(
            "model,requests,refused,errors,input_tokens,output_tokens,total_tokens,spend_usd,latency_p50_ms,latency_p95_ms"
        )
    );
    assert!(
        lines.any(|l| l.starts_with("\"m\",2,0,0,20,10,30,")),
        "{csv}"
    );

    // A wrong group is refused with what to send.
    let (status, _, _, body) = call(
        &gw.router,
        "GET",
        "/admin/usage?group_by=colour",
        Some(ROOT),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("day, hour or one of"), "{body}");

    // see_spend is needed; a role kept to an organization sees its own.
    let (status, _, _, body) = call(&gw.router, "GET", "/admin/usage", Some(LOOK), "").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("see_spend"), "{body}");
    let (status, _, _, body) = call(
        &gw.router,
        "GET",
        "/admin/usage?group_by=team",
        Some(FIN),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let usage = json(&body);
    assert_eq!(usage["totals"]["requests"], 2, "{usage}");
    assert!(
        usage["groups"]
            .as_array()
            .is_some_and(|g| g.iter().all(|r| r["team"] != "search"))
    );
    let (status, _, _, body) =
        call(&gw.router, "GET", "/admin/usage?org=globex", Some(FIN), "").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    Ok(())
}

#[tokio::test]
async fn a_policy_kept_in_the_file_is_read_but_not_changed_through_the_api() -> TestResult {
    let port = provider().await?;
    let dir = dir("file")?;
    let gw = gateway(&dir, &policy(port, ""), None)?;
    let (status, _, _, body) = call(&gw.router, "GET", "/admin/rules", Some(LOOK), "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["rules"][0]["name"], "everyone");
    let (status, _, _, body) =
        call(&gw.router, "GET", "/admin/providers/mock", Some(ROOT), "").await?;
    assert_eq!(
        (status, json(&body)["kind"].clone()),
        (StatusCode::OK, json!("openai")),
        "{body}"
    );
    let (status, _, _, body) = call(&gw.router, "GET", "/admin/models", Some(ROOT), "").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["models"][0]["price"]["input"], 1, "{body}");
    // Teams list keys, so they need see_keys: a spend-only role is refused (tests/teams.rs covers roles kept to
    // teams seeing their own).
    let (status, _, _, body) = call(&gw.router, "GET", "/admin/teams", Some(FIN), "").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["error"]["code"], "not_permitted", "{body}");
    let (status, _, _, body) = call(&gw.router, "GET", "/admin/teams", Some(LOOK), "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("dana.levi") && body.contains("maya.cohen"),
        "{body}"
    );

    let rule = json!({"principals": {"team": "payments"}, "models": ["m"]}).to_string();
    let (status, _, _, body) = call(
        &gw.router,
        "PUT",
        "/admin/rules/payments",
        Some(ROOT),
        &rule,
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["error"]["code"], "policy_in_file");
    let (status, _, _, body) = call(
        &gw.router,
        "PUT",
        "/admin/rules/payments",
        Some(LOOK),
        &rule,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("edit_policy"), "{body}");
    Ok(())
}

async fn database(test: &str) -> Result<Option<enterplace_server::store::TestDatabase>, Error> {
    enterplace_server::store::TestDatabase::create(&format!(
        "enterplace_{}_{test}",
        std::process::id()
    ))
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn each_part_of_the_policy_is_managed_as_new_versions_with_records() -> TestResult {
    let Some(url) = database("admin_sections").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let dir = dir("sections")?;
    let gw = gateway(
        &dir,
        &policy(
            port,
            "store: { postgres_url_env: ENTERPLACE_STORE_URL, policy_from: store }\n",
        ),
        Some(url.to_string()),
    )?;
    let audit = dir.join("enterplace-audit.jsonl");
    for (name, team, key, admin) in [
        ("root", "ops", ROOT, true),
        ("maya.cohen", "payments", MAYA, false),
    ] {
        enterplace_core::keyfile::add_entry(name, team, key, admin, &gw.loaded.keys_path)?;
    }
    gw.reloader.check(enterplace_server::Trigger::FileChange);

    // A rule, added then read back: version 2, live, with its record.
    let rule = json!({"principals": {"team": "payments"}, "models": ["m"]}).to_string();
    let (status, decision, _, body) = call(
        &gw.router,
        "PUT",
        "/admin/rules/payments",
        Some(ROOT),
        &rule,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        (json(&body)["version"].clone(), json(&body)["state"].clone()),
        (json!(2), json!("live"))
    );
    gw.log.flush();
    let record = admin_record(&audit, &decision)?;
    assert_eq!(record["action"], "put_rule");
    assert_eq!(record["target"]["name"], "payments");
    let (_, _, _, body) = call(&gw.router, "GET", "/admin/rules/payments", Some(ROOT), "").await?;
    assert_eq!(json(&body)["principals"]["team"], "payments", "{body}");

    // A stale If-Match is refused; a guardrail, an alias, budgets, a model and a price each make a version.
    let (status, _, _, body) = call(
        &gw.router,
        "DELETE",
        "/admin/rules/payments",
        Some(ROOT),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _, _, body) = call(
        &gw.router,
        "DELETE",
        "/admin/rules/payments",
        Some(ROOT),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let budgets = json!([{"team": "payments", "budget": {"usd": 50, "per": "month"}}]).to_string();
    let (status, _, _, body) =
        call(&gw.router, "PUT", "/admin/budgets", Some(ROOT), &budgets).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (_, _, _, body) = call(&gw.router, "GET", "/admin/budgets", Some(ROOT), "").await?;
    let budgets = json(&body);
    let payments = budgets["limits"]
        .as_array()
        .and_then(|b| b.iter().find(|b| b["team"] == "payments").cloned())
        .ok_or("no payments budget")?;
    assert_eq!(payments["budget"]["usd"], 50, "{budgets}");
    let model =
        json!({"provider": "mock", "model": "o", "input": 0.5, "output": 1.5, "aliases": ["fast"]})
            .to_string();
    let (status, decision, _, body) =
        call(&gw.router, "POST", "/admin/models", Some(ROOT), &model).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    gw.log.flush();
    assert_eq!(admin_record(&audit, &decision)?["action"], "add_model");
    let (status, _, _, body) = call(
        &gw.router,
        "PUT",
        "/admin/models/o/price",
        Some(ROOT),
        r#"{"input": 0.25, "output": 1}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (_, _, _, body) = call(&gw.router, "GET", "/admin/aliases/fast", Some(ROOT), "").await?;
    assert_eq!(json(&body)["deployments"][0]["model"], "o", "{body}");
    let (_, _, _, text) = call(&gw.router, "GET", "/admin/policy", Some(ROOT), "").await?;
    assert!(
        text.contains("o: { input: 0.25, output: 1 }") || text.contains("input: 0.25"),
        "{text}"
    );
    let (status, _, _, body) = call(
        &gw.router,
        "PUT",
        "/admin/rules/x",
        Some(ROOT),
        r#"{"principals": {"anyone": true}}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"]["code"], "invalid_policy");
    let mut request = Request::put("/admin/rules/payments")
        .header(header::AUTHORIZATION, format!("Bearer {ROOT}"))
        .header(header::IF_MATCH, "\"1\"");
    request = request.header(header::CONTENT_TYPE, "application/json");
    let response = gw
        .router
        .clone()
        .oneshot(request.body(Body::from(rule))?)
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    Ok(())
}
