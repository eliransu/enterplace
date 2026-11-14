//! Observe mode and `shadow_until` on rules, budgets and limits: what the policy would refuse is forwarded and
//! recorded as `would_refuse`, and still counted. A missing, bad or revoked key, an unknown model and a kill switch
//! are refused as always: observing never opens the gateway.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use gantry_server::{Governed, Reload, Trigger};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const PAT: &str = "gantry_pat_0123456789abcdef0123456789ab";
const CARL: &str = "gantry_carl_0123456789abcdef0123456789a";
const NOBODY: &str = "gantry_nobody_0123456789abcdef01234567";
const ADMIN: &str = "gantry_admin_0123456789abcdef012345678";

/// A provider that counts the requests it gets. Every answer reports 1000 prompt tokens and 1 output token.
async fn provider() -> Result<(Arc<AtomicUsize>, u16), Error> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |_: Bytes| async move {
            counted.fetch_add(1, Ordering::SeqCst);
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"id":"c","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":1}}"#,
                ))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((hits, port))
}

/// `m` costs $0.001 for each output token and nothing for input, so each answer costs $0.001.
fn policy(port: u16, top: &str, rules: &str) -> String {
    format!(
        "version: 1
{top}providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [m, m2]
prices:
  m: {{ input: 0, output: 1000 }}
  m2: {{ input: 0, output: 1000 }}
guardrails:
  - name: no-secrets
    type: secrets
    action: block
rules:
{rules}"
    )
}

const RULES: &str = "  - name: payments
    principals: { team: payments }
    models: [m]
    budget: { usd: 0.0015, per: day }
    guardrails: [no-secrets]
";

fn entry(name: &str, team: &str, key: &str) -> String {
    format!(
        "  - name: {name}\n    team: {team}\n    sha256: {}\n",
        sha256_hex(key.as_bytes())
    )
}

struct Setup {
    gw: Governed,
    policy: PathBuf,
    audit: PathBuf,
    hits: Arc<AtomicUsize>,
    port: u16,
}

async fn setup(name: &str, top: &str, rules: &str) -> Result<Setup, Error> {
    let (hits, port) = provider().await?;
    let dir = std::env::temp_dir().join(format!("gantry-observe-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(&path, policy(port, top, rules))?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}{}{}    admin: true\n",
            entry("pat", "payments", PAT),
            entry("carl", "cap", CARL),
            entry("nobody", "elsewhere", NOBODY),
            entry("ops", "ops", ADMIN)
        ),
    )?;
    let gw = gantry_server::governed(&path, None, &|_| Some("provider-secret".into()))?;
    Ok(Setup {
        gw,
        policy: path,
        audit: dir.join("gantry-audit.jsonl"),
        hits,
        port,
    })
}

fn chat(key: &str, model: &str, text: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(format!(
            r#"{{"model":"{model}","max_tokens":1,"messages":[{{"role":"user","content":"{text}"}}]}}"#
        )))
}

/// Status, the error code if any, and the decision ID.
async fn send(app: &Router, request: Request<Body>) -> Result<(StatusCode, String, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let decision = response
        .headers()
        .get("x-gantry-decision")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = response.into_body().collect().await?.to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let code = body["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok((status, code, decision))
}

/// The decision record of a decision.
fn record(audit: &Path, id: &str) -> Result<Value, Error> {
    std::fs::read_to_string(audit)?
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|r| r["id"] == id && r.get("event").is_none())
        .ok_or_else(|| format!("no decision record for {id}").into())
}

fn would_refuse(record: &Value) -> Vec<String> {
    record["would_refuse"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|w| w["code"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_forwards_what_a_budget_would_refuse_and_records_would_refuse() -> TestResult {
    let s = setup("budget", "mode: observe\n", RULES).await?;
    let app = &s.gw.router;

    let (status, _, first) = send(app, chat(PAT, "m", "hi")?).await?;
    assert_eq!(status, StatusCode::OK);
    let first = record(&s.audit, &first)?;
    assert_eq!(first["verdict"], "allow");
    assert!(first.get("outcome").is_none(), "{first}");

    // $0.001 spent and $0.001 more would pass the $0.0015 budget: forwarded, and on record.
    let (status, _, second) = send(app, chat(PAT, "m", "hi")?).await?;
    assert_eq!(status, StatusCode::OK);
    let second = record(&s.audit, &second)?;
    assert_eq!(second["verdict"], "allow", "{second}");
    assert_eq!(second["outcome"], "would_refuse", "{second}");
    assert_eq!(would_refuse(&second), ["budget_exceeded"], "{second}");
    assert_eq!(second["would_refuse"][0]["by"], "observe", "{second}");

    // The second one was charged too, so the numbers are real when enforcement starts.
    let (status, _, third) = send(app, chat(PAT, "m", "hi")?).await?;
    assert_eq!(status, StatusCode::OK);
    let third = record(&s.audit, &third)?;
    let message = third["would_refuse"][0]["message"].as_str().unwrap_or("");
    assert!(message.contains("has spent $0.0020"), "{third}");
    assert_eq!(s.hits.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_forwards_what_the_rules_and_guardrails_would_refuse() -> TestResult {
    let s = setup("rules", "mode: observe\n", RULES).await?;
    let app = &s.gw.router;

    // A model the rule does not allow, a caller no rule names, and a secret a guardrail blocks.
    for (key, model, text, code) in [
        (PAT, "m2", "hi", "model_not_allowed"),
        (NOBODY, "m", "hi", "no_rule"),
        (
            PAT,
            "m",
            "AKIAIOSFODNN7EXAMPLE is my key",
            "guardrail_blocked",
        ),
    ] {
        let (status, refused, id) = send(app, chat(key, model, text)?).await?;
        assert_eq!(status, StatusCode::OK, "{code}: {refused}");
        let record = record(&s.audit, &id)?;
        assert_eq!(record["outcome"], "would_refuse", "{record}");
        assert!(
            would_refuse(&record).contains(&code.to_string()),
            "{record}"
        );
    }
    assert_eq!(s.hits.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_still_refuses_missing_key() -> TestResult {
    let s = setup("key", "mode: observe\n", RULES).await?;
    let app = &s.gw.router;
    let no_key =
        Request::post("/v1/chat/completions").body(Body::from(r#"{"model":"m","messages":[]}"#))?;
    let (status, code, _) = send(app, no_key).await?;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "no_key")
    );
    let (status, code, _) = send(
        app,
        chat("gantry_not_a_key_000000000000000000000", "m", "hi")?,
    )
    .await?;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "unknown_key")
    );
    assert_eq!(s.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_still_refuses_unknown_model() -> TestResult {
    let s = setup("model", "mode: observe\n", RULES).await?;
    let (status, code, _) = send(&s.gw.router, chat(PAT, "nope", "hi")?).await?;
    assert_eq!(code, "unknown_model", "{status}");
    assert_eq!(s.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_still_honours_kill_switch() -> TestResult {
    let s = setup("kill", "mode: observe\n", RULES).await?;
    let app = &s.gw.router;
    let kill = Request::post("/admin/kills")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::from(
            r#"{"scope":"model","value":"m","reason":"runaway agent"}"#,
        ))?;
    let response = app.clone().oneshot(kill).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let (status, code, _) = send(app, chat(PAT, "m", "hi")?).await?;
    assert_eq!((status, code.as_str()), (StatusCode::FORBIDDEN, "killed"));
    assert_eq!(s.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_to_enforce_takes_effect_on_next_request() -> TestResult {
    let s = setup("reload", "mode: observe\n", RULES).await?;
    let app = &s.gw.router;
    let (status, _, _) = send(app, chat(PAT, "m2", "hi")?).await?;
    assert_eq!(status, StatusCode::OK);

    std::fs::write(&s.policy, policy(s.port, "", RULES))?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    let (status, code, _) = send(app, chat(PAT, "m2", "hi")?).await?;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::FORBIDDEN, "model_not_allowed")
    );
    assert_eq!(s.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn check_warns_on_observe() -> TestResult {
    let dir = std::env::temp_dir().join(format!("gantry-observe-{}-check", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(dir.join("gantry.keys.yaml"), "keys: []\n")?;

    std::fs::write(&path, policy(1, "mode: observe\n", RULES))?;
    let loaded = gantry_core::config::load(&path, None).map_err(|e| e.join("\n"))?;
    let warnings = gantry_core::config::warnings(&path, &loaded).join("\n");
    assert!(warnings.contains("mode: observe"), "{warnings}");
    assert!(warnings.contains("nothing is refused"), "{warnings}");

    std::fs::write(&path, policy(1, "mode: enforce\n", RULES))?;
    let loaded = gantry_core::config::load(&path, None).map_err(|e| e.join("\n"))?;
    assert!(
        !gantry_core::config::warnings(&path, &loaded)
            .join("\n")
            .contains("observe")
    );

    std::fs::write(&path, policy(1, "mode: watch\n", RULES))?;
    let Err(errors) = gantry_core::config::load(&path, None) else {
        return Err("mode: watch was accepted".into());
    };
    let errors = errors.join("\n");
    assert!(
        errors.contains("mode") && errors.contains("observe") && errors.contains("enforce"),
        "{errors}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn shadowed_budget_forwards_and_records_while_other_budgets_enforce() -> TestResult {
    let rules = "  - name: payments
    principals: { team: payments }
    models: [m]
    budget: { usd: 0.0015, per: day, shadow_until: 2999-01-01 }
  - name: cap
    principals: { team: cap }
    models: [m]
    budget: { usd: 0.0015, per: day }
";
    let s = setup("shadow-budget", "", rules).await?;
    let app = &s.gw.router;
    for key in [PAT, CARL] {
        assert_eq!(send(app, chat(key, "m", "hi")?).await?.0, StatusCode::OK);
    }
    let (status, _, id) = send(app, chat(PAT, "m", "hi")?).await?;
    assert_eq!(status, StatusCode::OK);
    let shadowed = record(&s.audit, &id)?;
    assert_eq!(would_refuse(&shadowed), ["budget_exceeded"], "{shadowed}");
    assert_eq!(
        shadowed["would_refuse"][0]["by"], "shadow_until",
        "{shadowed}"
    );
    let (status, code, _) = send(app, chat(CARL, "m", "hi")?).await?;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "budget_exceeded")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn shadowed_rule_and_limits_entry_forward_and_record() -> TestResult {
    let top = "limits:
  - person: pat
    rate: { rpm: 1 }
    shadow_until: 2999-01-01T00:00:00Z
";
    let rules = "  - name: payments
    principals: { team: payments }
    models: [m]
    shadow_until: 2999-01-01
";
    let s = setup("shadow-rule", top, rules).await?;
    let app = &s.gw.router;
    assert_eq!(send(app, chat(PAT, "m", "hi")?).await?.0, StatusCode::OK);
    let (status, _, id) = send(app, chat(PAT, "m2", "hi")?).await?;
    assert_eq!(status, StatusCode::OK);
    let record = record(&s.audit, &id)?;
    let codes = would_refuse(&record);
    assert!(codes.contains(&"model_not_allowed".to_string()), "{record}");
    assert!(codes.contains(&"rate_limited".to_string()), "{record}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn past_shadow_until_enforces() -> TestResult {
    let rules = "  - name: payments
    principals: { team: payments }
    models: [m]
    budget: { usd: 0.0015, per: day, shadow_until: 2020-01-01 }
";
    let s = setup("shadow-past", "", rules).await?;
    let app = &s.gw.router;
    assert_eq!(send(app, chat(PAT, "m", "hi")?).await?.0, StatusCode::OK);
    let (status, code, _) = send(app, chat(PAT, "m", "hi")?).await?;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "budget_exceeded")
    );
    Ok(())
}

#[test]
fn malformed_shadow_until_is_refused_by_check_with_path() -> TestResult {
    let dir = std::env::temp_dir().join(format!("gantry-observe-{}-malformed", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(dir.join("gantry.keys.yaml"), "keys: []\n")?;
    let budget = "  - name: payments
    principals: { team: payments }
    models: [m]
    budget: { usd: 1, per: day, shadow_until: next week }
";
    let budgets = "  - name: payments
    principals: { team: payments }
    models: [m]
    budget:
      - { usd: 1, per: day }
      - { usd: 9, per: month, shadow_until: 2026-13-01 }
";
    let rule = "  - name: payments
    principals: { team: payments }
    models: [m]
    shadow_until: soon
";
    let limits = "limits:\n  - team: payments\n    rate: { rpm: 5 }\n    shadow_until: tomorrow\n";
    for (top, rules, want) in [
        ("", budget, "rules[0].budget.shadow_until"),
        ("", budgets, "rules[0].budget[1].shadow_until"),
        ("", rule, "rules[0].shadow_until"),
        (limits, RULES, "limits[0].shadow_until"),
    ] {
        std::fs::write(&path, policy(1, top, rules))?;
        let Err(errors) = gantry_core::config::load(&path, None) else {
            return Err(format!("{want}: accepted").into());
        };
        let errors = errors.join("\n");
        assert!(errors.contains(want), "{want}: {errors}");
        assert!(
            errors.contains("2026-12-31"),
            "the fix names a date: {errors}"
        );
    }
    Ok(())
}
