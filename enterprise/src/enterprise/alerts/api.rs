//! Alert rules in the admin API (`/admin/alerts/...`), as the Alerts page edits them. The gateway checks the key, the
//! permission (`see_records` to read, `edit_policy` to change) and writes the admin record before each call; this
//! does the change. Channels are listed without their secrets and are added on the page, where a signing secret can
//! be shown once.

use std::sync::Arc;

use axum::http::StatusCode;
use gantry_console::Form;
use gantry_core::{policy::Permission, store::Pending};
use gantry_server::{AdminApi, AdminCall, AdminRoute};
use serde_json::{Value, json};

use super::{Engine, Rule, RuleKind, db_error};

fn route(
    method: &'static str,
    path: &'static str,
    action: &'static str,
    permission: Permission,
    summary: &'static str,
) -> AdminRoute {
    AdminRoute {
        method,
        path,
        action,
        permission: Some(permission),
        summary,
    }
}

fn routes() -> Vec<AdminRoute> {
    use Permission::{EditPolicy, SeeRecords};
    vec![
        route(
            "GET",
            "/admin/alerts",
            "list_alerts",
            SeeRecords,
            "The alerts fired lately, newest first (enterprise)",
        ),
        route(
            "GET",
            "/admin/alerts/channels",
            "list_alert_channels",
            SeeRecords,
            "The alert channels, never their secrets (enterprise)",
        ),
        route(
            "GET",
            "/admin/alerts/rules",
            "list_alert_rules",
            SeeRecords,
            "The alert rules (enterprise)",
        ),
        route(
            "POST",
            "/admin/alerts/rules",
            "add_alert_rule",
            EditPolicy,
            "Adds an alert rule (enterprise)",
        ),
        route(
            "PUT",
            "/admin/alerts/rules/{id}",
            "update_alert_rule",
            EditPolicy,
            "Replaces an alert rule (enterprise)",
        ),
        route(
            "DELETE",
            "/admin/alerts/rules/{id}",
            "remove_alert_rule",
            EditPolicy,
            "Removes an alert rule; its past alerts stay (enterprise)",
        ),
    ]
}

fn refusal(status: StatusCode, code: &str, message: impl Into<String>) -> (StatusCode, Value) {
    (
        status,
        json!({ "error": { "message": format!("Refused: {}", message.into()), "type": "gantry_error", "code": code } }),
    )
}

/// The admin API of the alerts feature, or of its absence: without the license each route says why.
pub enum AlertsApi {
    On(Arc<Engine>),
    Locked { code: &'static str, message: String },
}

impl AdminApi for AlertsApi {
    fn routes(&self) -> Vec<AdminRoute> {
        routes()
    }

    fn call(&self, call: AdminCall) -> Pending<(StatusCode, Value)> {
        let engine = match self {
            Self::On(engine) => engine.clone(),
            Self::Locked { code, message } => {
                let answer = refusal(StatusCode::FORBIDDEN, code, message.clone());
                return Box::pin(async move { Ok(answer) });
            }
        };
        Box::pin(async move { Ok(answer(&engine, call).await) })
    }
}

/// A form's text from a rule's JSON `params`, so the page's checks apply as they are.
fn form_of(params: &Value) -> Form {
    let enc = |text: &str| {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    let pairs: Vec<String> = params
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| {
            let text = match v {
                Value::String(s) => s.clone(),
                Value::Bool(true) => "on".into(),
                Value::Number(n) => n.to_string(),
                _ => return None,
            };
            Some(format!("{}={}", enc(k), enc(&text)))
        })
        .collect();
    Form::parse(&pairs.join("&"))
}

fn rule_json(rule: &Rule) -> Value {
    json!({
        "id": rule.id,
        "name": rule.name,
        "kind": rule.kind.word(),
        "params": rule.params,
        "channels": rule.channels,
        "enabled": rule.enabled,
        "cooldown_minutes": rule.cooldown,
        "max_per_hour": rule.max_per_hour,
        "describes": rule.describe(),
    })
}

async fn answer(engine: &Engine, call: AdminCall) -> (StatusCode, Value) {
    match run(engine, call).await {
        Ok(answer) => answer,
        Err(err) => refusal(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", err),
    }
}

async fn run(engine: &Engine, call: AdminCall) -> Result<(StatusCode, Value), String> {
    let (rules, channels) = engine.load().await?;
    let id: i64 = call
        .params
        .first()
        .and_then(|p| p.parse().ok())
        .unwrap_or(-1);
    match call.action {
        "list_alert_rules" => Ok((
            StatusCode::OK,
            json!({ "rules": rules.iter().map(rule_json).collect::<Vec<_>>(), "kinds": super::RULE_KINDS.iter().map(|k| json!({ "kind": k.word(), "label": k.label() })).collect::<Vec<_>>() }),
        )),
        "list_alert_channels" => Ok((
            StatusCode::OK,
            json!({ "channels": channels.iter().map(|c| json!({ "id": c.id, "kind": c.kind.word(), "name": c.name })).collect::<Vec<_>>() }),
        )),
        "list_alerts" => {
            let client = engine.db.client().await?;
            let rows = client
                .query(
                    "SELECT id, rule, rule_name, kind, key, summary, evidence, to_char(fired_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), delivery \
                     FROM enterprise_alerts ORDER BY id DESC LIMIT 200",
                    &[],
                )
                .await
                .map_err(db_error)?;
            let mut alerts = Vec::new();
            for r in rows {
                alerts.push(json!({
                    "id": r.try_get::<_, i64>(0).map_err(db_error)?,
                    "rule": r.try_get::<_, i64>(1).map_err(db_error)?,
                    "rule_name": r.try_get::<_, String>(2).map_err(db_error)?,
                    "kind": r.try_get::<_, String>(3).map_err(db_error)?,
                    "subject": r.try_get::<_, String>(4).map_err(db_error)?,
                    "summary": r.try_get::<_, String>(5).map_err(db_error)?,
                    "records": serde_json::from_str::<Value>(&r.try_get::<_, String>(6).map_err(db_error)?).unwrap_or(Value::Null),
                    "fired_at": r.try_get::<_, String>(7).map_err(db_error)?,
                    "delivery": r.try_get::<_, String>(8).map_err(db_error)?,
                }));
            }
            Ok((StatusCode::OK, json!({ "alerts": alerts })))
        }
        "remove_alert_rule" => {
            let client = engine.db.client().await?;
            let changed = client
                .execute("DELETE FROM enterprise_alert_rules WHERE id = $1", &[&id])
                .await
                .map_err(db_error)?;
            if changed == 0 {
                return Ok(no_rule(id));
            }
            Ok((StatusCode::OK, json!({ "removed": id })))
        }
        _ => {
            let body = &call.body;
            let bad = |m: String| refusal(StatusCode::BAD_REQUEST, "invalid_rule", m);
            let Some(kind) = body["kind"].as_str().and_then(RuleKind::parse) else {
                return Ok(bad(format!(
                    "kind is one of {}.",
                    super::RULE_KINDS
                        .iter()
                        .map(|k| k.word())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            };
            let name: String = body["name"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .chars()
                .take(100)
                .collect();
            if name.is_empty() {
                return Ok(bad("name the rule, for example {\"name\": \"Payments spend\", \"kind\": \"budget\", \"params\": {...}}.".into()));
            }
            let params = match Rule::check(kind, &form_of(&body["params"])) {
                Ok(params) => params,
                Err(err) => return Ok(bad(err)),
            };
            let wanted: Vec<i64> = body["channels"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_i64)
                .collect();
            if let Some(missing) = wanted
                .iter()
                .find(|w| !channels.iter().any(|c| c.id == **w))
            {
                return Ok(bad(format!(
                    "there is no channel {missing}. GET /admin/alerts/channels lists them."
                )));
            }
            let cooldown = body["cooldown_minutes"].as_i64().unwrap_or(60);
            let max_per_hour = body["max_per_hour"].as_i64().unwrap_or(10);
            if !(0..=10_080).contains(&cooldown) || !(1..=1000).contains(&max_per_hour) {
                return Ok(bad(
                    "cooldown_minutes is 0 to 10080 and max_per_hour 1 to 1000.".into(),
                ));
            }
            let (cooldown, max_per_hour) = (cooldown as i32, max_per_hour as i32);
            let enabled = body["enabled"].as_bool().unwrap_or(true);
            let channel_list = wanted
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let client = engine.db.client().await?;
            let id = if call.action == "update_alert_rule" {
                let changed = client
                    .execute(
                        "UPDATE enterprise_alert_rules SET name = $2, kind = $3, params = $4, channels = $5, cooldown_minutes = $6, \
                         max_per_hour = $7, enabled = $8, updated_by = $9, updated_at = now() WHERE id = $1",
                        &[&id, &name, &kind.word(), &params.to_string(), &channel_list, &cooldown, &max_per_hour, &enabled, &call.by],
                    )
                    .await
                    .map_err(db_error)?;
                if changed == 0 {
                    return Ok(no_rule(id));
                }
                id
            } else {
                client
                    .query_one(
                        "INSERT INTO enterprise_alert_rules (name, kind, params, channels, cooldown_minutes, max_per_hour, enabled, updated_by) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
                        &[&name, &kind.word(), &params.to_string(), &channel_list, &cooldown, &max_per_hour, &enabled, &call.by],
                    )
                    .await
                    .map_err(db_error)?
                    .try_get(0)
                    .map_err(db_error)?
            };
            let rule = Rule {
                id,
                name,
                kind,
                params,
                channels: wanted,
                enabled,
                cooldown,
                max_per_hour,
            };
            let status = if call.action == "add_alert_rule" {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            Ok((status, json!({ "rule": rule_json(&rule) })))
        }
    }
}

fn no_rule(id: i64) -> (StatusCode, Value) {
    refusal(
        StatusCode::NOT_FOUND,
        "no_such_rule",
        format!("there is no alert rule {id}. GET /admin/alerts/rules lists them."),
    )
}
