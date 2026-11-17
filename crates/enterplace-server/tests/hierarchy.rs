//! Acceptance tests for the access and budget hierarchy: organizations, customers, tags, scope limits, parallel
//! limits, the explanation and console roles on the admin API. The mock provider listens on a port the system picks.

use std::{
    path::Path,
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

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const SHOP: &str = "enterplace_shop_0123456789abcdef0123456789a";
const GLOB: &str = "enterplace_glob_0123456789abcdef0123456789a";
const FIN: &str = "enterplace_fin0_0123456789abcdef0123456789a";
const ROOT: &str = "enterplace_root_0123456789abcdef0123456789a";

/// A stream whose events come from a channel, so a test can hold it open.
struct Feed(tokio::sync::mpsc::Receiver<Bytes>);

impl futures_core::Stream for Feed {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|item| item.map(Ok))
    }
}

/// Every answer costs 1 output token of model `m`, a tenth of a cent. A body with "hold" keeps its answer open for
/// 30 seconds after the first piece.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move {
            let hold = body.windows(6).any(|w| w == b"\"hold\"");
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let _ = tx
                    .send(Bytes::from_static(br#"{"id":"c","choices":[],"#))
                    .await;
                if hold {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                let _ = tx
                    .send(Bytes::from_static(
                        br#""usage":{"prompt_tokens":0,"completion_tokens":1}}"#,
                    ))
                    .await;
            });
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from_stream(Feed(rx)))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16) -> String {
    format!(
        "version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [m, n]
prices:
  m: {{ input: 0, output: 1000 }}
  n: {{ input: 0, output: 1000 }}
orgs: [acme, globex]
profiles:
  - name: shop
    models: [m, n]
    tags: []
rules:
  - name: acme-shop
    org: acme
    principals: {{ team: shop }}
    profiles: [shop]
    customers: [\"*\"]
    tags: [search]
  - name: globex-all
    org: globex
    principals: {{ any: true }}
    models: [m]
  - name: admins
    principals: {{ any: true }}
    models: []
limits:
  - {{ customer: \"*\", budget: {{ usd: 0.0015, per: day }} }}
  - {{ tag: search, budget: {{ usd: 0.0035, per: week }} }}
  - {{ model: n, budget: {{ usd: 0.0015, per: 6h, tz: Europe/Berlin }} }}
  - {{ org: globex, parallel: 1 }}
roles:
  - name: finance
    permissions: [see_spend]
"
    )
    // The profile above has a `tags:` key profiles do not take: replaced below by a valid one per test.
    .replace("    tags: []\n", "")
}

fn keys() -> String {
    let entry = |name: &str, team: &str, key: &str, extra: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n{extra}",
            sha256_hex(key.as_bytes())
        )
    };
    format!(
        "keys:\n{}{}{}{}",
        entry("shop-backend", "shop", SHOP, "    org: acme\n"),
        entry("glob", "apps", GLOB, "    org: globex\n"),
        entry("fin", "money", FIN, "    org: acme\n    role: finance\n"),
        entry("root", "ops", ROOT, "    admin: true\n"),
    )
}

struct Setup {
    gw: enterplace_server::Governed,
    audit: std::path::PathBuf,
}

async fn setup(name: &str) -> Result<Setup, Error> {
    let port = provider().await?;
    let dir = std::env::temp_dir().join(format!("enterplace-hier-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, self::policy(port))?;
    std::fs::write(dir.join("enterplace.keys.yaml"), keys())?;
    Ok(Setup {
        gw: enterplace_server::governed(&policy, None, &|_| Some("provider-secret".into()))?,
        audit: dir.join("enterplace-audit.jsonl"),
    })
}

fn chat(
    key: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(body.to_string()))
}

fn get(key: &str, path: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::empty())
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn records(path: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

/// The usage record of the request refused or allowed last with `code`, waiting for the usage to be written.
async fn usage_count(audit: &Path, n: usize) -> Result<Vec<Value>, Error> {
    let start = Instant::now();
    loop {
        let usage: Vec<Value> = records(audit)?
            .into_iter()
            .filter(|r| r["event"] == "usage")
            .collect();
        if usage.len() >= n {
            return Ok(usage);
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err(format!("{} usage records, not {n}", usage.len()).into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const ONE: &str = r#"{"model":"m","max_tokens":1,"messages":[]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn each_customer_has_its_own_budget_and_a_caller_names_only_what_its_rule_lets() -> TestResult
{
    let s = setup("customers").await?;
    let app = &s.gw.router;
    let globex = [
        ("x-enterplace-customer", "globex-shop"),
        ("x-enterplace-tags", "search"),
    ];
    let (status, body) = answer(app, chat(SHOP, ONE, &globex)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    usage_count(&s.audit, 1).await?;
    // $0.001 spent of $0.0015: another $0.001 would pass the customer's budget.
    let (status, body) = answer(app, chat(SHOP, ONE, &globex)?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "budget_exceeded");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("customer \"acme/globex-shop\" has spent $0.0010 of its $0.0015 budget")
            && message.contains("set by limits { customer: * }"),
        "{message}"
    );
    // Another customer has a budget of its own.
    let initech = [("x-enterplace-customer", "initech")];
    let (status, body) = answer(app, chat(SHOP, ONE, &initech)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A tag the rule does not list is refused by name, and so is a customer under a rule that lists none.
    let (status, body) = answer(app, chat(SHOP, ONE, &[("x-enterplace-tags", "forged")])?).await?;
    assert_eq!(
        (status, &body["error"]["code"]),
        (StatusCode::FORBIDDEN, &Value::from("tag_not_allowed"))
    );
    let (status, body) = answer(app, chat(GLOB, ONE, &initech)?).await?;
    assert_eq!(
        (status, &body["error"]["code"]),
        (StatusCode::FORBIDDEN, &Value::from("customer_not_allowed")),
        "{body}"
    );
    let all = records(&s.audit)?;
    let refused = all
        .iter()
        .find(|r| r["code"] == "budget_exceeded")
        .ok_or("no refusal record")?;
    assert_eq!(refused["applied"]["of"], "customer");
    assert_eq!(refused["applied"]["scope"], "customer:acme/globex-shop");
    assert_eq!(refused["customer"], "globex-shop");
    assert_eq!(refused["org"], "acme");
    let usage = usage_count(&s.audit, 2).await?;
    assert_eq!(usage[0]["customer"], "globex-shop");
    assert_eq!(usage[0]["tags"], serde_json::json!(["search"]));
    assert_eq!(usage[0]["org"], "acme");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parallel_limit_holds_a_place_until_the_answer_ends() -> TestResult {
    let s = setup("parallel").await?;
    let app = &s.gw.router;
    let held = app
        .clone()
        .oneshot(chat(
            GLOB,
            r#"{"model":"m","max_tokens":1,"messages":[],"hold":true}"#,
            &[],
        )?)
        .await?;
    assert_eq!(held.status(), StatusCode::OK);
    let response = app.clone().oneshot(chat(GLOB, ONE, &[])?).await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["error"]["code"], "parallel_limited");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("organization \"globex\" already has 1 requests in flight")),
        "{body}"
    );
    // The caller hangs up: its place is given back.
    drop(held);
    let start = Instant::now();
    loop {
        let (status, body) = answer(app, chat(GLOB, ONE, &[])?).await?;
        if status == StatusCode::OK {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(3), "{body}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_explanation_lists_each_limit_with_its_source_and_spend_for_a_role_that_may_see_it()
-> TestResult {
    let s = setup("explain").await?;
    let app = &s.gw.router;
    let (status, _) = answer(
        app,
        chat(
            SHOP,
            r#"{"model":"n","max_tokens":1,"messages":[]}"#,
            &[("x-enterplace-customer", "c1")],
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    usage_count(&s.audit, 1).await?;
    let shop = &sha256_hex(SHOP.as_bytes())[..8];
    let path = format!("/admin/explain?key={shop}&model=n&customer=c1&tags=search");
    let (status, explained) = answer(app, get(FIN, &path)?).await?;
    assert_eq!(status, StatusCode::OK, "{explained}");
    assert_eq!(explained["verdict"], "allow");
    assert_eq!(explained["rule"]["name"], "acme-shop");
    assert_eq!(explained["rule"]["profiles"], serde_json::json!(["shop"]));
    assert_eq!(explained["skipped"], serde_json::json!([]));
    let limits = explained["limits"].as_array().ok_or("no limits")?;
    let find = |of: &str| {
        limits
            .iter()
            .find(|l| l["of"] == of)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(find("customer")["scope"], "customer:acme/c1");
    assert!(
        find("customer")["spent_usd"]
            .as_f64()
            .is_some_and(|v| (v - 0.001).abs() < 1e-9),
        "{explained}"
    );
    assert_eq!(find("tag")["per"], "week");
    assert_eq!(find("model")["per"], "6h@Europe/Berlin");
    assert!(
        find("model")["resets"]
            .as_str()
            .is_some_and(|r| r.ends_with("Europe/Berlin"))
    );
    assert!(
        find("model")["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("limits { model: n }"))
    );
    // The finance role may see spend and not keys; it is kept to its key's organization.
    let (status, body) = answer(app, get(FIN, "/admin/keys")?).await?;
    assert_eq!(
        (status, &body["error"]["code"]),
        (StatusCode::FORBIDDEN, &Value::from("not_permitted"))
    );
    let glob = &sha256_hex(GLOB.as_bytes())[..8];
    let (status, body) = answer(
        app,
        get(FIN, &format!("/admin/explain?key={glob}&model=m"))?,
    )
    .await?;
    assert_eq!(
        (status, &body["error"]["code"]),
        (StatusCode::NOT_FOUND, &Value::from("no_such_key"))
    );
    // An admin of the whole install sees every key, with its organization.
    let (status, body) = answer(app, get(ROOT, "/admin/keys")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["keys"]
            .as_array()
            .is_some_and(|k| k.iter().any(|k| k["org"] == "globex"))
    );
    // A key with neither admin nor a role has no admin API.
    let (status, body) = answer(app, get(GLOB, "/admin/keys")?).await?;
    assert_eq!(
        (status, &body["error"]["code"]),
        (StatusCode::FORBIDDEN, &Value::from("not_admin"))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn per_org_each_organizations_records_are_its_own_chain_and_spend_survives_a_restart()
-> TestResult {
    let s = setup("per-org").await?;
    let dir = s.audit.parent().ok_or("no folder")?.to_path_buf();
    let policy = dir.join("enterplace.policy.yaml");
    let text = std::fs::read_to_string(&policy)?;
    std::fs::write(&policy, format!("{text}audit: {{ per_org: true }}\n"))?;
    let audit = s.audit.clone();
    drop(s);
    let start = || enterplace_server::governed(&policy, None, &|_| Some("provider-secret".into()));
    let gw = start()?;
    let shop = [("x-enterplace-customer", "globex-shop")];
    let (status, body) = answer(&gw.router, chat(SHOP, ONE, &shop)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = answer(&gw.router, chat(GLOB, ONE, &[])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let acme = enterplace_core::audit::org_path(&audit, "acme");
    let globex = enterplace_core::audit::org_path(&audit, "globex");
    usage_count(&acme, 1).await?;
    usage_count(&globex, 1).await?;
    gw.log.flush();
    // Each organization's request and usage are in its chain alone; the install keeps what names none.
    let install = records(&audit)?;
    assert!(install.iter().any(|r| r["event"] == "config_loaded"));
    assert!(
        !install.iter().any(|r| r.get("org").is_some()),
        "{install:?}"
    );
    for (chain, org) in [(&acme, "acme"), (&globex, "globex")] {
        let mine = records(chain)?;
        assert!(mine.iter().all(|r| r["org"] == org), "{mine:?}");
        assert!(mine.iter().any(|r| r["verdict"] == "allow"));
        assert_eq!(enterplace_core::audit::verify(chain)?.0, 2);
    }
    enterplace_core::audit::verify(&audit)?;
    // The request log folds every chain.
    let rows = enterplace_core::insights::fold_chain(&audit)?;
    assert_eq!(rows.iter().filter(|r| r.verdict == "allow").count(), 2);
    // Spend is read back from every chain at start: the customer's $0.001 still counts against its $0.0015.
    drop(gw);
    let gw = start()?;
    let (status, body) = answer(&gw.router, chat(SHOP, ONE, &shop)?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "budget_exceeded");
    gw.log.flush();
    assert_eq!(
        enterplace_core::audit::verify(&acme)?.0,
        3,
        "the refusal goes on its chain"
    );
    Ok(())
}
