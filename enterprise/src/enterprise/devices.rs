//! Devices (license feature `devices`): enrolment tokens for the device agent (`enterplace device`), the device
//! profile it reads, the reports it sends, and the console's Devices page, which merges those reports with the audit
//! log's traffic per person: tools seen, enrolled devices, and devices with a tool calling a provider directly.
//!
//! Ported from the Cloudflare app's devices.ts. One org per install, so a token is scoped to the install or to one
//! team. Tokens are kept as SHA-256, expire, and are revoked from the console or the admin API
//! (`/console/devices/tokens`, an admin key as bearer). Every change is an admin record, written before it is made.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Extension as Ext, Router,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use enterplace_console::{
    Admin, Console, Form, Tls, bare_page, foreign,
    html::{self, esc},
    redirect, same_origin,
};
use enterplace_core::{config, coverage, id::sha256_hex};
use enterplace_server::sql::Sql;
use enterplace_server::store::tokio_postgres::types::ToSql;
use serde_json::{Value, json};

use super::Db;
use super::members::origin;
use super::siem::{
    Role, banner, db_error, hidden, input, random_hex, role_of, section, small_button,
};
use crate::device::{DEFAULT_MANAGED, MANAGEABLE, TOOLS, app_names, why_not};
use crate::license::Status;

pub const FEATURE: &str = "devices";

pub const MIGRATION: &str = "
CREATE TABLE enterprise_device_tokens (
    id text PRIMARY KEY,
    label text NOT NULL,
    team text NOT NULL DEFAULT '',
    token_sha256 text NOT NULL UNIQUE,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE TABLE enterprise_device_profiles (
    team text PRIMARY KEY,
    gateway_url text NOT NULL,
    tools text NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_devices (
    device_id text PRIMARY KEY,
    hostname text NOT NULL,
    os_user text NOT NULL,
    person text NOT NULL,
    team text NOT NULL DEFAULT '',
    agent_version text NOT NULL DEFAULT '',
    token_id text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_device_tools (
    device_id text NOT NULL REFERENCES enterprise_devices (device_id) ON DELETE CASCADE,
    tool text NOT NULL,
    state text NOT NULL,
    endpoints text NOT NULL DEFAULT '[]',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, tool)
);
CREATE TABLE enterprise_device_drift (
    id bigserial PRIMARY KEY,
    device_id text NOT NULL,
    person text NOT NULL,
    tool text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
";

/// The organization an enrolment token belongs to, for installs with `orgs:`. Empty for none. An admin whose role
/// is kept to one organization sees and revokes its tokens alone.
pub const MIGRATION_4: &str = "
ALTER TABLE enterprise_device_tokens ADD COLUMN org text NOT NULL DEFAULT '';
";

/// A device is bound to the first person and token scope (the token's team, empty for every team) that reported
/// it; a report from another is refused and kept here. Never edit a migration that has shipped: add one.
pub const MIGRATION_2: &str = "
ALTER TABLE enterprise_devices ADD COLUMN token_scope text;
CREATE TABLE enterprise_device_refusals (
    id bigserial PRIMARY KEY,
    device_id text NOT NULL,
    person text NOT NULL,
    token_id text NOT NULL,
    reason text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
";

/// The OS each device runs, the MCP servers its tools are configured with (from the agent's inventory), and the
/// admin's decision on each server, by its transport and target: approved or blocked. A server with no decision is
/// pending.
pub const MIGRATION_3: &str = "
ALTER TABLE enterprise_devices ADD COLUMN os text NOT NULL DEFAULT '';
CREATE TABLE enterprise_device_mcp (
    device_id text NOT NULL REFERENCES enterprise_devices (device_id) ON DELETE CASCADE,
    tool text NOT NULL,
    file text NOT NULL,
    server text NOT NULL,
    transport text NOT NULL,
    target text NOT NULL,
    via_enterplace boolean NOT NULL,
    PRIMARY KEY (device_id, tool, file, server)
);
CREATE TABLE enterprise_mcp_decisions (
    transport text NOT NULL,
    target text NOT NULL,
    decision text NOT NULL,
    decided_by text NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (transport, target)
);
";

/// What a profile says beyond the tools to manage: the AI apps it allows and denies (comma lists of
/// `device::app_names`), and whether approved MCP servers are pointed at Enterplace's MCP gateway. What each device
/// found of those apps, and each blocked MCP server the agent took out of a tool's file or sent through the gateway.
pub const MIGRATION_5: &str = "
ALTER TABLE enterprise_device_profiles ADD COLUMN apps_allowed text NOT NULL DEFAULT '';
ALTER TABLE enterprise_device_profiles ADD COLUMN apps_denied text NOT NULL DEFAULT '';
ALTER TABLE enterprise_device_profiles ADD COLUMN mcp_via_gateway boolean NOT NULL DEFAULT false;
CREATE TABLE enterprise_device_apps (
    device_id text NOT NULL REFERENCES enterprise_devices (device_id) ON DELETE CASCADE,
    app text NOT NULL,
    status text NOT NULL,
    running boolean NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, app)
);
CREATE TABLE enterprise_device_mcp_actions (
    id bigserial PRIMARY KEY,
    device_id text NOT NULL,
    person text NOT NULL,
    tool text NOT NULL,
    server text NOT NULL,
    transport text NOT NULL,
    target text NOT NULL,
    action text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
";

/// What the agent does with a blocked MCP server it finds: `report` it (the default) or `remove` it from the tool's
/// file, keeping the file as it was beside it.
pub const MIGRATION_6: &str = "
ALTER TABLE enterprise_device_profiles ADD COLUMN mcp_enforcement text NOT NULL DEFAULT 'report';
";

/// The header the agent sends the person's Enterplace key in (the one `enterplace login` saved), beside the enrolment token.
pub const PERSON_HEADER: &str = "x-enterplace-key";

const NAV: &str = "Devices";
const PREFIX: &str = "enterplace_dev_";
const DEFAULT_DAYS: i32 = 90;
const MAX_DAYS: i32 = 365;
const STATES: [&str; 4] = ["not_installed", "installed", "enterplace", "direct"];
const TIME: &str = r#"'YYYY-MM-DD"T"HH24:MI:SS"Z"'"#;

#[derive(Clone)]
struct Devices {
    db: Arc<Db>,
    keys: PathBuf,
    policy: enterplace_server::PolicyNow,
}

/// Adds the device routes the agent calls and the console's Devices page and API.
pub fn register(
    extension: &mut enterplace_server::Extension,
    db: Arc<Db>,
    keys: PathBuf,
    policy: enterplace_server::PolicyNow,
) {
    let devices = Devices { db, keys, policy };
    let agent = Router::new()
        .route("/device/profile", get(profile))
        .route("/device/report", post(report))
        .layer(Ext(devices.clone()));
    extension.routes = std::mem::take(&mut extension.routes).merge(agent);
    let console = &mut extension.console;
    console.nav.push(("/console/devices".into(), NAV.into()));
    console.routes = std::mem::take(&mut console.routes)
        .route("/devices", get(page).post(act))
        .route("/devices/devices.json", get(devices_json))
        .route("/devices/tokens", get(list_tokens).post(create_token_api))
        .route("/devices/tokens/{id}", delete(revoke_token_api))
        .route("/devices/devices/{id}", delete(remove_device_api))
        .route("/devices/mcp", get(list_mcp_api).post(decide_mcp_api))
        .layer(Ext(devices));
}

/// Without the feature the page and the agent's routes say why, and there is no nav entry.
pub fn locked(extension: &mut enterplace_server::Extension, status: &Status) {
    let Err(refused) = status.require(FEATURE) else {
        return;
    };
    let (code, message) = (refused.code, refused.message);
    let text = message.clone();
    let page = move || {
        let message = text.clone();
        async move {
            bare_page(
                StatusCode::FORBIDDEN,
                "Devices need a license",
                &format!(
                    r#"<h1 class="t-lg" style="margin: 0">Devices need a license</h1><p class="t-lead g-muted" style="margin: 0">{}</p><p class="t-small g-muted" style="margin: 0">Code: {code}</p>"#,
                    esc(&message)
                ),
            )
        }
    };
    let api = move || {
        let message = message.clone();
        async move { fail(StatusCode::FORBIDDEN, code, &message) }
    };
    extension.routes = std::mem::take(&mut extension.routes).merge(
        Router::new()
            .route("/device/profile", get(api.clone()))
            .route("/device/report", post(api)),
    );
    let console = &mut extension.console;
    console.routes = std::mem::take(&mut console.routes).route("/devices", get(page));
}

/// A JSON body: axum's `Json` needs a feature this crate leaves off, for one line.
pub(super) struct Json(pub(super) Value);

impl IntoResponse for Json {
    fn into_response(self) -> Response {
        (
            [(header::CONTENT_TYPE, "application/json")],
            self.0.to_string(),
        )
            .into_response()
    }
}

pub(super) fn fail(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

pub(super) fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.get(..7)
                .filter(|b| b.eq_ignore_ascii_case("bearer "))
                .map(|_| &v[7..])
        })
        .unwrap_or("")
        .trim()
}

/// A gateway URL a device may be sent to: https, or http on this machine, without a query.
fn valid_gateway(url: &str) -> bool {
    let local = ["http://localhost", "http://127.0.0.1"].iter().any(|l| {
        url.strip_prefix(l)
            .is_some_and(|r| r.is_empty() || r.starts_with([':', '/']))
    });
    (url.starts_with("https://") && url.len() > 8 || local) && !url.contains(['?', '#', ' '])
}

struct Token {
    id: String,
    team: String,
}

/// The key holder whose key this is, if the key is in the keys file (or the store) and not expired.
pub(super) fn key_holder(keys: &std::path::Path, key: &str) -> Option<config::KeyEntry> {
    if key.is_empty() {
        return None;
    }
    let text = config::read_keys(keys).ok()??;
    let sha = sha256_hex(key.as_bytes());
    let now = enterplace_core::audit::timestamp();
    config::key_entries(keys, &text)
        .ok()?
        .into_iter()
        .find(|e| e.sha256 == sha)
        .filter(|e| {
            e.expires
                .as_deref()
                .is_none_or(|at| !enterplace_core::policy::expiry_passed(at, &now))
        })
}

impl Devices {
    fn holder(&self, key: &str) -> Option<config::KeyEntry> {
        key_holder(&self.keys, key)
    }

    /// The person at the device, from the Enterplace key it sent in `x-enterplace-key`, never from what the report says.
    /// `Err` is the refusal's code and message.
    fn person(
        &self,
        headers: &HeaderMap,
    ) -> Result<config::KeyEntry, (&'static str, &'static str)> {
        let key = headers
            .get(PERSON_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim();
        if key.is_empty() {
            return Err((
                "person_key_required",
                "Send the person's Enterplace key in the x-enterplace-key header, as the device agent does once someone has run `enterplace login` on the machine. The gateway takes the person from that key, not from the report.",
            ));
        }
        self.holder(key).ok_or((
            "invalid_person_key",
            "The key in x-enterplace-key is not a Enterplace key, or it expired or was revoked. Run `enterplace login` again on the machine.",
        ))
    }

    /// The enrolment token the device sent, if it is one that works now.
    async fn enrolled(&self, headers: &HeaderMap) -> Result<Token, Response> {
        let token = bearer(headers);
        let invalid = || {
            fail(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Send the enrolment token as Authorization: Bearer enterplace_dev_... (set ENTERPLACE_DEVICE_TOKEN). An owner or admin creates one on the console's Devices page; a revoked token stops working.",
            )
        };
        if !token.starts_with(PREFIX) {
            return Err(invalid());
        }
        let unavailable =
            |e: String| fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e);
        let client = self.db.client().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                &format!("SELECT id, team, expires_at < now(), to_char(expires_at AT TIME ZONE 'UTC', {TIME}) FROM enterprise_device_tokens WHERE token_sha256 = $1 AND revoked_at IS NULL"),
                &[&sha256_hex(token.as_bytes())],
            )
            .await
            .map_err(|e| unavailable(db_error(e)))?
            .ok_or_else(invalid)?;
        let get = |i| row.try_get::<_, String>(i).unwrap_or_default();
        if row.try_get::<_, bool>(2).unwrap_or(true) {
            return Err(fail(
                StatusCode::UNAUTHORIZED,
                "token_expired",
                &format!(
                    "This enrolment token expired at {}. Create a new one on the console's Devices page and give it to your MDM.",
                    get(3)
                ),
            ));
        }
        Ok(Token {
            id: get(0),
            team: get(1),
        })
    }

    /// The tokens `admin` may see: every one, or those within their role's organization and teams.
    async fn tokens(&self, admin: &Admin) -> Result<Vec<Value>, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                &format!("SELECT id, label, team, created_by, to_char(created_at AT TIME ZONE 'UTC', {TIME}), to_char(expires_at AT TIME ZONE 'UTC', {TIME}), \
                 CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at < now() THEN 'expired' ELSE 'active' END, org \
                 FROM enterprise_device_tokens ORDER BY created_at"),
                &[],
            )
            .await
            .map_err(db_error)?;
        Ok(rows
            .iter()
            .map(|r| {
                let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
                json!({ "id": get(0), "label": get(1), "team": get(2), "org": get(7), "created_by": get(3), "created_at": get(4), "expires_at": get(5), "status": get(6) })
            })
            .filter(|t| {
                admin.covers(
                    t["org"].as_str().unwrap_or(""),
                    t["team"].as_str().unwrap_or(""),
                    None,
                )
            })
            .collect())
    }

    /// The devices `admin` may see as last reported, as `enterplace_core::coverage::Device` reads it: every one, or
    /// those of their role's teams enrolled with a token of their role's organization.
    async fn devices(&self, admin: &Admin) -> Result<Vec<Value>, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                &format!("SELECT d.device_id, d.hostname, d.os_user, d.person, d.team, d.agent_version, to_char(d.last_seen AT TIME ZONE 'UTC', {TIME}), \
                 (d.last_seen < now() - interval '24 hours'), coalesce(t.tool, ''), coalesce(t.state, ''), coalesce(t.endpoints, '[]'), d.os, coalesce(k.org, '') \
                 FROM enterprise_devices d LEFT JOIN enterprise_device_tools t ON t.device_id = d.device_id \
                 LEFT JOIN enterprise_device_tokens k ON k.id = d.token_id ORDER BY d.person, d.device_id, t.tool"),
                &[],
            )
            .await
            .map_err(db_error)?;
        let mut out: Vec<Value> = Vec::new();
        for r in &rows {
            let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
            let id = get(0);
            if !admin.covers(&get(12), &get(4), None) {
                continue;
            }
            if out.last().is_none_or(|d| d["device_id"] != id.as_str()) {
                out.push(json!({
                    "device_id": id, "hostname": get(1), "os_user": get(2), "person": get(3), "team": get(4), "org": get(12),
                    "agent_version": get(5), "last_seen": get(6), "stale": r.try_get::<_, bool>(7).unwrap_or(false), "os": get(11),
                    "tools": [], "mcp": [], "apps": [],
                }));
            }
            let tool = get(8);
            if let (false, Some(Value::Array(tools))) =
                (tool.is_empty(), out.last_mut().map(|d| &mut d["tools"]))
            {
                let endpoints: Value = serde_json::from_str(&get(10)).unwrap_or(json!([]));
                let mut row = json!({ "tool": tool, "state": get(9), "endpoints": endpoints });
                // A tool no documented file configures stays `installed`: say why.
                if let (true, Some(why)) = (get(9) == "installed", why_not(&tool)) {
                    row["note"] = why.into();
                }
                tools.push(row);
            }
        }
        let apps = client
            .query(
                "SELECT device_id, app, status, running FROM enterprise_device_apps ORDER BY device_id, app",
                &[],
            )
            .await
            .map_err(db_error)?;
        for r in &apps {
            let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
            let id = get(0);
            if let Some(Value::Array(list)) = out
                .iter_mut()
                .find(|d| d["device_id"] == id.as_str())
                .map(|d| &mut d["apps"])
            {
                list.push(json!({ "app": get(1), "status": get(2), "running": r.try_get::<_, bool>(3).unwrap_or(false) }));
            }
        }
        let servers = client
            .query(
                "SELECT m.device_id, m.tool, m.server, m.transport, m.target, m.via_enterplace, coalesce(x.decision, 'pending') \
                 FROM enterprise_device_mcp m LEFT JOIN enterprise_mcp_decisions x ON x.transport = m.transport AND x.target = m.target \
                 ORDER BY m.device_id, m.tool, m.server",
                &[],
            )
            .await
            .map_err(db_error)?;
        for r in &servers {
            let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
            let id = get(0);
            if let Some(Value::Array(list)) = out
                .iter_mut()
                .find(|d| d["device_id"] == id.as_str())
                .map(|d| &mut d["mcp"])
            {
                list.push(json!({
                    "tool": get(1), "server": get(2), "transport": get(3), "target": get(4),
                    "via_enterplace": r.try_get::<_, bool>(5).unwrap_or(false), "decision": get(6),
                }));
            }
        }
        Ok(out)
    }

    /// Every MCP server some device reported, once per transport and target: its names, the tools and devices that
    /// have it, whether it goes through Enterplace, and the admin's decision. Decided servers no device lists any more
    /// are kept, so a block outlives the configuration it was made for. An admin whose role keeps them to part of
    /// the install is shown the servers of the devices they may see, counted over those devices alone.
    async fn mcp_servers(&self, admin: &Admin) -> Result<Vec<Value>, String> {
        let within: Option<Vec<String>> = if admin.confined() {
            let devices = self.devices(admin).await?;
            Some(
                devices
                    .iter()
                    .filter_map(|d| d["device_id"].as_str().map(str::to_string))
                    .collect(),
            )
        } else {
            None
        };
        let client = self.db.client().await?;
        let rows = client
            .query(
                Sql::both(
                    format!("SELECT k.transport, k.target, coalesce(string_agg(DISTINCT m.server, ', '), ''), coalesce(string_agg(DISTINCT m.tool, ', '), ''), \
                     count(DISTINCT m.device_id), coalesce(bool_and(m.via_enterplace), false), coalesce(x.decision, 'pending'), coalesce(x.decided_by, ''), \
                     coalesce(to_char(x.decided_at AT TIME ZONE 'UTC', {TIME}), '') \
                     FROM (SELECT transport, target FROM enterprise_device_mcp WHERE $1::text[] IS NULL OR device_id = ANY($1) \
                     UNION SELECT transport, target FROM enterprise_mcp_decisions WHERE $1::text[] IS NULL) k \
                     LEFT JOIN enterprise_device_mcp m ON m.transport = k.transport AND m.target = k.target AND ($1::text[] IS NULL OR m.device_id = ANY($1)) \
                     LEFT JOIN enterprise_mcp_decisions x ON x.transport = k.transport AND x.target = k.target \
                     GROUP BY k.transport, k.target, x.decision, x.decided_by, x.decided_at ORDER BY k.target, k.transport"),
                    // SQLite: the device list is JSON text, and a DISTINCT group_concat takes no separator, so the
                    // names are joined in subqueries, sorted as Postgres sorts them for DISTINCT.
                    "SELECT k.transport, k.target, \
                     coalesce((SELECT group_concat(server, ', ') FROM (SELECT DISTINCT n.server FROM enterprise_device_mcp n WHERE n.transport = k.transport AND n.target = k.target \
                       AND (?1 IS NULL OR n.device_id IN (SELECT value FROM json_each(?1))) ORDER BY n.server)), ''), \
                     coalesce((SELECT group_concat(tool, ', ') FROM (SELECT DISTINCT n.tool FROM enterprise_device_mcp n WHERE n.transport = k.transport AND n.target = k.target \
                       AND (?1 IS NULL OR n.device_id IN (SELECT value FROM json_each(?1))) ORDER BY n.tool)), ''), \
                     count(DISTINCT m.device_id), coalesce(min(m.via_enterplace), 0), coalesce(x.decision, 'pending'), coalesce(x.decided_by, ''), \
                     coalesce(strftime('%Y-%m-%dT%H:%M:%SZ', x.decided_at), '') \
                     FROM (SELECT transport, target FROM enterprise_device_mcp WHERE ?1 IS NULL OR device_id IN (SELECT value FROM json_each(?1)) \
                     UNION SELECT transport, target FROM enterprise_mcp_decisions WHERE ?1 IS NULL) k \
                     LEFT JOIN enterprise_device_mcp m ON m.transport = k.transport AND m.target = k.target AND (?1 IS NULL OR m.device_id IN (SELECT value FROM json_each(?1))) \
                     LEFT JOIN enterprise_mcp_decisions x ON x.transport = k.transport AND x.target = k.target \
                     GROUP BY k.transport, k.target, x.decision, x.decided_by, x.decided_at ORDER BY k.target, k.transport",
                ),
                &[&within],
            )
            .await
            .map_err(db_error)?;
        Ok(rows
            .iter()
            .map(|r| {
                let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
                json!({
                    "transport": get(0), "target": get(1), "servers": get(2), "tools": get(3),
                    "devices": r.try_get::<_, i64>(4).unwrap_or(0), "via_enterplace": r.try_get::<_, bool>(5).unwrap_or(false),
                    "decision": get(6), "decided_by": get(7), "decided_at": get(8),
                })
            })
            .collect())
    }

    /// Approves or blocks an MCP server (or puts it back to pending), recorded first.
    async fn decide_mcp(
        &self,
        console: &Console,
        admin: &Admin,
        transport: &str,
        target: &str,
        decision: &str,
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let action = "device_mcp_decided";
        let details = json!({ "transport": transport, "target": target, "decision": decision });
        let problem = if role_of(admin) == Role::Viewer {
            Some((
                StatusCode::FORBIDDEN,
                "read_only",
                "Your role is viewer. An owner or admin can approve or block MCP servers."
                    .to_string(),
            ))
        } else if !matches!(transport, "http" | "stdio")
            || target.is_empty()
            || target.chars().count() > 500
        {
            Some((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Name the server by transport (http or stdio) and target (its URL, or its command's file name), as the Devices page lists it.".to_string(),
            ))
        } else if !matches!(decision, "approved" | "blocked" | "pending") {
            Some((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("{decision:?} is not a decision: send approved, blocked or pending."),
            ))
        } else {
            None
        };
        if let Some((status, code, message)) = problem {
            let _ = console
                .audit(Some(admin), action, details, Some(code))
                .await;
            return Err((status, code, message));
        }
        let unavailable = |e: String| (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", e);
        // A decision holds for every device with the server, so a role kept to part of the install decides only on
        // a server one of its own devices has.
        if admin.confined()
            && !self
                .mcp_servers(admin)
                .await
                .map_err(unavailable)?
                .iter()
                .any(|s| s["transport"] == transport && s["target"] == target)
        {
            let _ = console
                .audit(Some(admin), action, details, Some("outside_role"))
                .await;
            return Err((
                StatusCode::FORBIDDEN,
                "outside_role",
                "No device within your role has this MCP server, so it is not yours to decide. List yours with GET /console/devices/mcp, or ask an admin of the whole install.".into(),
            ));
        }
        console
            .audit(Some(admin), action, details, None)
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let client = self.db.client().await.map_err(unavailable)?;
        let done = if decision == "pending" {
            client
                .execute(
                    "DELETE FROM enterprise_mcp_decisions WHERE transport = $1 AND target = $2",
                    &[&transport, &target],
                )
                .await
        } else {
            client
                .execute(
                    "INSERT INTO enterprise_mcp_decisions (transport, target, decision, decided_by) VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (transport, target) DO UPDATE SET decision = excluded.decision, decided_by = excluded.decided_by, decided_at = now()",
                    &[&transport, &target, &decision, &admin.name],
                )
                .await
        };
        done.map(|_| ()).map_err(|e| unavailable(db_error(e)))
    }

    /// The decided servers, for the device profile: approved and blocked, each as {transport, target}.
    async fn mcp_decisions(&self) -> Result<Value, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                "SELECT transport, target, decision FROM enterprise_mcp_decisions ORDER BY target, transport",
                &[],
            )
            .await
            .map_err(db_error)?;
        let (mut approved, mut blocked) = (Vec::new(), Vec::new());
        for r in &rows {
            let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
            let server = json!({ "transport": get(0), "target": get(1) });
            if get(2) == "blocked" {
                blocked.push(server);
            } else {
                approved.push(server);
            }
        }
        Ok(json!({ "approved": approved, "blocked": blocked }))
    }

    /// Creates a token, recorded first. `Ok` is (id, token, expires_at).
    async fn create(
        &self,
        console: &Console,
        admin: &Admin,
        label: &str,
        team: &str,
        org: &str,
        days: i32,
    ) -> Result<(String, String, String), (StatusCode, &'static str, String)> {
        let label = label.trim();
        let team = team.trim();
        let bad = |message: String| (StatusCode::BAD_REQUEST, "invalid_request", message);
        let problem = if label.is_empty() || label.chars().count() > 64 {
            Some("Enter a label of 1 to 64 characters, such as jamf-engineering.".to_string())
        } else if !team.is_empty() && !config::valid_name(team) {
            Some(format!(
                "{team:?} is not a team name: use letters, digits, dot, dash or underscore, or leave it empty for every team."
            ))
        } else if !(1..=MAX_DAYS).contains(&days) {
            Some(format!(
                "A token lasts 1 to {MAX_DAYS} days; {days} is outside that."
            ))
        } else {
            None
        };
        if let Some(message) = problem {
            let _ = console
                .audit(
                    Some(admin),
                    "device_token_created",
                    json!({ "label": label }),
                    Some("invalid_request"),
                )
                .await;
            return Err(bad(message));
        }
        if role_of(admin) == Role::Viewer {
            let _ = console
                .audit(
                    Some(admin),
                    "device_token_created",
                    json!({}),
                    Some("read_only"),
                )
                .await;
            return Err((
                StatusCode::FORBIDDEN,
                "read_only",
                "Your role is viewer. An owner or admin can create enrolment tokens.".into(),
            ));
        }
        let orgs = self.policy.with(|p| p.orgs().to_vec()).unwrap_or_default();
        let org = token_org(admin, org, &orgs).and_then(|org| {
            match outside(admin, &org, team, "enrolment token") {
                Some(message) => Err((StatusCode::FORBIDDEN, "outside_role", message)),
                None => Ok(org),
            }
        });
        let org = match org {
            Ok(org) => org,
            Err(refusal) => {
                let _ = console
                    .audit(
                        Some(admin),
                        "device_token_created",
                        json!({ "label": label, "team": team }),
                        Some(refusal.1),
                    )
                    .await;
                return Err(refusal);
            }
        };
        let unavailable = |e: String| (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", e);
        let token = format!("{PREFIX}{}", random_hex(32).map_err(unavailable)?);
        let id = format!("dt-{}", random_hex(4).map_err(unavailable)?);
        console
            .audit(
                Some(admin),
                "device_token_created",
                json!({ "id": id, "label": label, "team": team, "org": org, "days": days }),
                None,
            )
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let client = self.db.client().await.map_err(unavailable)?;
        let row = client
            .query_one(
                &format!("INSERT INTO enterprise_device_tokens (id, label, team, token_sha256, created_by, expires_at, org) \
                 VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 day', $7) RETURNING to_char(expires_at AT TIME ZONE 'UTC', {TIME})"),
                // A float: Postgres reads `$6 * interval` as float8, and SQLite takes a fractional day count.
                &[&id, &label, &team, &sha256_hex(token.as_bytes()), &admin.name, &f64::from(days), &org],
            )
            .await
            .map_err(|e| unavailable(db_error(e)))?;
        Ok((id, token, row.try_get(0).unwrap_or_default()))
    }

    /// Revokes a token, recorded first. `Ok(false)` when there is no active token by that ID.
    async fn revoke(
        &self,
        console: &Console,
        admin: &Admin,
        id: &str,
    ) -> Result<bool, (StatusCode, &'static str, String)> {
        if role_of(admin) == Role::Viewer {
            let _ = console
                .audit(
                    Some(admin),
                    "device_token_revoked",
                    json!({ "id": id }),
                    Some("read_only"),
                )
                .await;
            return Err((
                StatusCode::FORBIDDEN,
                "read_only",
                "Your role is viewer. An owner or admin can revoke enrolment tokens.".into(),
            ));
        }
        let unavailable = |e: String| (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", e);
        // A token outside the role's reach is, to its holder, not there: neither revoked nor recorded as revoked.
        if admin.confined()
            && !self
                .tokens(admin)
                .await
                .map_err(unavailable)?
                .iter()
                .any(|t| t["id"] == id)
        {
            return Ok(false);
        }
        console
            .audit(
                Some(admin),
                "device_token_revoked",
                json!({ "id": id }),
                None,
            )
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let client = self.db.client().await.map_err(unavailable)?;
        let changed = client
            .execute("UPDATE enterprise_device_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", &[&id])
            .await
            .map_err(|e| unavailable(db_error(e)))?;
        Ok(changed > 0)
    }
}

// ---------------------------------------------------------------- the agent's routes

async fn profile(Ext(d): Ext<Devices>, headers: HeaderMap, tls: Tls) -> Response {
    let token = match d.enrolled(&headers).await {
        Ok(token) => token,
        Err(refused) => return refused,
    };
    // A team token decides the team; otherwise the person's key does. A device without one (nobody ran `enterplace
    // login` yet) gets the profile for every team: what it says about its person is not taken.
    let holder = d.person(&headers).ok();
    let person = holder.as_ref().map(|h| h.name.clone()).unwrap_or_default();
    let team = if token.team.is_empty() {
        holder.map(|h| h.team).unwrap_or_default()
    } else {
        token.team
    };
    let row = match d.db.client().await {
        Ok(client) => client
            .query_opt(
                "SELECT gateway_url, tools, apps_allowed, apps_denied, mcp_via_gateway, mcp_enforcement FROM enterprise_device_profiles WHERE team = $1 OR team = '' ORDER BY team = '' LIMIT 1",
                &[&team],
            )
            .await
            .map_err(db_error),
        Err(e) => Err(e),
    };
    let (gateway, tools, allowed, denied, via_gateway, enforcement) = match row {
        Ok(Some(r)) => {
            let list = |i| names(&r.try_get::<_, String>(i).unwrap_or_default());
            (
                r.try_get::<_, String>(0).unwrap_or_default(),
                list(1),
                list(2),
                list(3),
                r.try_get::<_, bool>(4).unwrap_or(false),
                r.try_get::<_, String>(5)
                    .unwrap_or_else(|_| "report".into()),
            )
        }
        // The device reached this gateway, so without a profile that is where its tools go.
        Ok(None) => (
            origin(&headers, &tls),
            DEFAULT_MANAGED
                .iter()
                .map(|t| (*t).to_string())
                .collect::<Vec<_>>(),
            Vec::new(),
            Vec::new(),
            false,
            "report".to_string(),
        ),
        Err(e) => return fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    };
    let mut mcp = match d.mcp_decisions().await {
        Ok(mcp) => mcp,
        Err(e) => return fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    };
    mcp["via_gateway"] = via_gateway.into();
    mcp["enforcement"] = enforcement.into();
    Json(json!({
        "gateway_url": gateway, "tools": tools, "team": team, "person": person, "mcp": mcp,
        "apps": { "allowed": allowed, "denied": denied },
    }))
    .into_response()
}

/// The names of a comma list, as a profile keeps its tools and apps.
fn names(list: &str) -> Vec<String> {
    list.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn text_of(body: &Value, field: &str, max: usize) -> Option<String> {
    body[field]
        .as_str()
        .filter(|v| !v.is_empty() && v.chars().count() <= max)
        .map(str::to_string)
}

/// The OSes the agent reports, as it names them.
const OSES: [&str; 3] = ["macos", "linux", "windows"];
/// What a profile's app lists make of an installed app.
const APP_STATUSES: [&str; 3] = ["allowed", "denied", "unlisted"];
/// The most MCP servers kept for one device: a report listing more keeps the first ones.
const MAX_MCP: usize = 200;

/// One MCP server a tool on a device is configured with, as the agent's inventory reports it.
struct McpServer {
    tool: String,
    file: String,
    server: String,
    transport: String,
    target: String,
    via_enterplace: bool,
}

impl McpServer {
    /// A well-formed inventory row; a row for a file that could not be read, or one with missing fields, is none.
    fn from_report(row: &Value) -> Option<Self> {
        let transport = text_of(row, "transport", 10).filter(|t| t == "http" || t == "stdio")?;
        Some(Self {
            tool: text_of(row, "tool", 50)?,
            file: text_of(row, "file", 500).unwrap_or_default(),
            server: text_of(row, "server", 200)?,
            target: bare_target(&text_of(row, "target", 500)?),
            transport,
            via_enterplace: row["via_enterplace"].as_bool().unwrap_or(false),
        })
    }
}

/// A target without a query, fragment or login, so a token an old agent left in a URL is never stored.
fn bare_target(target: &str) -> String {
    let target = target.split(['?', '#']).next().unwrap_or_default();
    match target.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
            format!("{scheme}://{host}{path}")
        }
        None => target.to_string(),
    }
}

async fn report(Ext(d): Ext<Devices>, headers: HeaderMap, body: String) -> Response {
    let token = match d.enrolled(&headers).await {
        Ok(token) => token,
        Err(refused) => return refused,
    };
    let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let (Some(device_id), Some(hostname), Some(os_user)) = (
        text_of(&body, "device_id", 200),
        text_of(&body, "hostname", 200),
        text_of(&body, "os_user", 100),
    ) else {
        return fail(
            StatusCode::BAD_REQUEST,
            "invalid_report",
            "The report needs device_id, hostname and os_user as strings of at most 200 characters. Send it as the device agent does (enterplace device).",
        );
    };
    let holder = match d.person(&headers) {
        Ok(holder) => holder,
        Err((code, message)) => return fail(StatusCode::UNAUTHORIZED, code, message),
    };
    let person = holder.name;
    let team = if token.team.is_empty() {
        holder.team
    } else {
        token.team.clone()
    };
    let version = text_of(&body, "agent_version", 50).unwrap_or_default();
    // Only the tools the agent knows, once each; an agent from before the `state` field says it with booleans.
    let mut tools: BTreeMap<String, (String, String, bool)> = BTreeMap::new();
    for t in body["tools"].as_array().into_iter().flatten() {
        let Some(tool) = t["tool"].as_str().filter(|n| TOOLS.contains(n)) else {
            continue;
        };
        let installed = t["installed"].as_bool().unwrap_or(false);
        let state = match t["state"].as_str() {
            Some(s) if STATES.contains(&s) => s,
            _ if !installed => "not_installed",
            _ if t["configured"].as_bool().unwrap_or(false) => "enterplace",
            _ => "installed",
        };
        let endpoints: Vec<String> = t["endpoints"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e.as_str().map(|e| e.chars().take(200).collect()))
            .take(8)
            .collect();
        let endpoints = serde_json::to_string(&endpoints).unwrap_or_else(|_| "[]".into());
        tools.insert(
            tool.to_string(),
            (
                state.to_string(),
                endpoints,
                t["drift"].as_bool().unwrap_or(false),
            ),
        );
    }
    let os = text_of(&body, "os", 20).filter(|os| OSES.contains(&os.as_str()));
    // An agent from before the inventory sends no `mcp`: its device keeps what it last listed.
    let mcp: Option<Vec<McpServer>> = body.get("mcp").map(|list| {
        list.as_array()
            .into_iter()
            .flatten()
            .filter_map(McpServer::from_report)
            .take(MAX_MCP)
            .collect()
    });
    // The apps the agent found, each one it knows once; an agent from before app lists sends none, and its device
    // keeps what it last listed.
    let known_apps = app_names();
    let apps: Option<BTreeMap<String, (String, bool)>> = body.get("apps").map(|list| {
        list.as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                let app = a["app"].as_str().filter(|n| known_apps.contains(n))?;
                let status = a["status"]
                    .as_str()
                    .filter(|s| APP_STATUSES.contains(s))
                    .unwrap_or("unlisted");
                Some((
                    app.to_string(),
                    (status.to_string(), a["running"].as_bool().unwrap_or(false)),
                ))
            })
            .collect()
    });
    // What the agent did to the tools' MCP files in this pass.
    let actions: Vec<(McpServer, String)> = body["mcp_actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let action = row["action"]
                .as_str()
                .filter(|a| matches!(*a, "removed" | "rewritten"))?;
            Some((McpServer::from_report(row)?, action.to_string()))
        })
        .take(MAX_MCP)
        .collect();
    let stored = async {
        let mut client = d.db.client().await?;
        // The writes land together through `atomic`, whose first statement updates the device only while it is
        // bound as read here: a report that raced another's binding changes no row, writes nothing, and reads again.
        for _ in 0..3 {
            // The first report binds the device to its person and token scope; a device from before the binding
            // keeps its person and takes the scope of its next report.
            let bound = client
                .query_opt(
                    "SELECT person, token_scope FROM enterprise_devices WHERE device_id = $1",
                    &[&device_id],
                )
                .await
                .map_err(db_error)?;
            if let Some(row) = bound {
                let was: String = row.try_get(0).unwrap_or_default();
                let scope: Option<String> = row.try_get(1).unwrap_or_default();
                let reason = if was != person {
                    Some(format!("bound to person {was}"))
                } else if scope.as_ref().is_some_and(|s| *s != token.team) {
                    Some(format!(
                        "bound to the token scope {}",
                        scope
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("every team")
                    ))
                } else {
                    None
                };
                if let Some(reason) = reason {
                    client
                        .execute(
                            "INSERT INTO enterprise_device_refusals (device_id, person, token_id, reason) VALUES ($1, $2, $3, $4)",
                            &[&device_id, &person, &token.id, &reason],
                        )
                        .await
                        .map_err(db_error)?;
                    return Ok::<_, String>(Some(reason));
                }
            }
            let mut writes: Vec<(Sql, Vec<&(dyn ToSql + Sync)>, Option<u64>)> = vec![(
                "INSERT INTO enterprise_devices (device_id, hostname, os_user, person, team, agent_version, token_id, token_scope) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (device_id) DO UPDATE SET hostname = excluded.hostname, os_user = excluded.os_user, team = excluded.team, \
                 agent_version = excluded.agent_version, token_id = excluded.token_id, token_scope = excluded.token_scope, last_seen = now() \
                 WHERE enterprise_devices.person = excluded.person AND (enterprise_devices.token_scope IS NULL OR enterprise_devices.token_scope = excluded.token_scope)".into(),
                vec![&device_id, &hostname, &os_user, &person, &team, &version, &token.id, &token.team],
                Some(1),
            )];
            if let Some(os) = &os {
                writes.push((
                    "UPDATE enterprise_devices SET os = $2 WHERE device_id = $1".into(),
                    vec![&device_id, os],
                    None,
                ));
            }
            if let Some(mcp) = &mcp {
                writes.push((
                    "DELETE FROM enterprise_device_mcp WHERE device_id = $1".into(),
                    vec![&device_id],
                    None,
                ));
                for m in mcp {
                    writes.push((
                        "INSERT INTO enterprise_device_mcp (device_id, tool, file, server, transport, target, via_enterplace) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING".into(),
                        vec![&device_id, &m.tool, &m.file, &m.server, &m.transport, &m.target, &m.via_enterplace],
                        None,
                    ));
                }
            }
            if let Some(apps) = &apps {
                writes.push((
                    "DELETE FROM enterprise_device_apps WHERE device_id = $1".into(),
                    vec![&device_id],
                    None,
                ));
                for (app, (status, running)) in apps {
                    writes.push((
                        "INSERT INTO enterprise_device_apps (device_id, app, status, running) VALUES ($1, $2, $3, $4)".into(),
                        vec![&device_id, app, status, running],
                        None,
                    ));
                }
            }
            for (m, action) in &actions {
                writes.push((
                    "INSERT INTO enterprise_device_mcp_actions (device_id, person, tool, server, transport, target, action) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)".into(),
                    vec![&device_id, &person, &m.tool, &m.server, &m.transport, &m.target, action],
                    None,
                ));
            }
            for (tool, (state, endpoints, drift)) in &tools {
                writes.push((
                    "INSERT INTO enterprise_device_tools (device_id, tool, state, endpoints) VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (device_id, tool) DO UPDATE SET state = excluded.state, endpoints = excluded.endpoints, updated_at = now()".into(),
                    vec![&device_id, tool, state, endpoints],
                    None,
                ));
                if *drift {
                    writes.push((
                        "INSERT INTO enterprise_device_drift (device_id, person, tool) VALUES ($1, $2, $3)".into(),
                        vec![&device_id, &person, tool],
                        None,
                    ));
                }
            }
            if client.atomic(writes).await.map_err(db_error)? {
                return Ok(None);
            }
        }
        Err(format!(
            "Device {device_id} was bound by another report while this one was stored, three times over. Send the report again."
        ))
    };
    match stored.await {
        Ok(None) => Json(json!({ "ok": true, "person": person, "team": team })).into_response(),
        Ok(Some(reason)) => fail(
            StatusCode::FORBIDDEN,
            "device_bound",
            &format!(
                "Refused: device {device_id} is {reason}, from its first report. If the machine changed hands, an owner or admin removes the device (DELETE /console/devices/devices/<device_id>) and its next report binds it again."
            ),
        ),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

// ---------------------------------------------------------------- the admin API

/// Who an admin API call is from: a console session, or an admin key as bearer. Either way with the role's reach:
/// a key whose role is kept to an organization, teams or customers is kept to them here too.
pub(super) async fn api_admin(
    console: &Console,
    keys: &std::path::Path,
    headers: &HeaderMap,
) -> Option<Admin> {
    let key = bearer(headers);
    if key.is_empty() {
        return console.signed_in(headers).await;
    }
    console.admin_of_key(&key_holder(keys, key).filter(|e| e.admin)?)
}

/// The organization a new token is for: the one asked for, else its creator's (someone kept to one organization
/// makes tokens for it alone). `Err` when their role is kept to another, or the policy lists no such organization.
pub(super) fn token_org(
    admin: &Admin,
    asked: &str,
    orgs: &[String],
) -> Result<String, (StatusCode, &'static str, String)> {
    let asked = asked.trim();
    let org = if asked.is_empty() {
        admin.org.clone().unwrap_or_default()
    } else {
        asked.to_string()
    };
    if let Some(own) = admin.org.as_ref().filter(|own| **own != org) {
        return Err((
            StatusCode::FORBIDDEN,
            "other_org",
            format!(
                "Your role is kept to organization {own}. Leave org out, or ask an owner for a token of {org:?}."
            ),
        ));
    }
    if !org.is_empty() && !orgs.contains(&org) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!(
                "{org:?} is not an organization of this gateway. Leave org out, or use one the policy lists under orgs: {}.",
                if orgs.is_empty() {
                    "none".to_string()
                } else {
                    orgs.join(", ")
                }
            ),
        ));
    }
    Ok(org)
}

/// Why `admin` may not make or touch a token of this organization and team, when their role keeps them from it.
/// A token for every team is outside a role kept to some teams, and no token is within a role kept to customers:
/// a token names no customer.
pub(super) fn outside(admin: &Admin, org: &str, team: &str, what: &str) -> Option<String> {
    if admin.covers(org, team, None) {
        return None;
    }
    let mut reach = Vec::new();
    if let Some(org) = &admin.org {
        reach.push(format!("organization {org}"));
    }
    if !admin.teams.is_empty() {
        reach.push(format!("teams {}", admin.teams.join(", ")));
    }
    if !admin.customers.is_empty() {
        reach.push(format!("customers {}", admin.customers.join(", ")));
    }
    let fix = if admin.customers.is_empty() {
        "Name a team and organization within it, or ask an admin of the whole install."
    } else {
        "A token names no customer, so ask an admin of the whole install."
    };
    Some(format!(
        "Your role is kept to {}, and this {what} is outside it. {fix}",
        reach.join(" and ")
    ))
}

pub(super) fn not_admin() -> Response {
    fail(
        StatusCode::UNAUTHORIZED,
        "admin_required",
        "Send an admin key (admin: true in the keys file) as Authorization: Bearer enterplace_..., or sign in to the console.",
    )
}

async fn list_tokens(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
) -> Response {
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    match d.tokens(&admin).await {
        Ok(tokens) => Json(json!({ "tokens": tokens })).into_response(),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

async fn create_token_api(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // A browser's cookie alone must not create tokens from another site.
    if bearer(&headers).is_empty() && !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let days = body["days"]
        .as_i64()
        .map_or(DEFAULT_DAYS, |n| i32::try_from(n).unwrap_or(i32::MAX));
    match d
        .create(&console, &admin, body["label"].as_str().unwrap_or(""), body["team"].as_str().unwrap_or(""), body["org"].as_str().unwrap_or(""), days)
        .await
    {
        Ok((id, token, expires)) => (
            StatusCode::CREATED,
            Json(json!({ "id": id, "token": token, "expires_at": expires, "note": "Enterplace keeps only the token's hash and cannot show it again." })),
        )
            .into_response(),
        Err((status, code, message)) => fail(status, code, &message),
    }
}

async fn revoke_token_api(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Response {
    if bearer(&headers).is_empty() && !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    match d.revoke(&console, &admin, &id).await {
        Ok(true) => Json(json!({ "id": id, "status": "revoked" })).into_response(),
        Ok(false) => fail(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("No active enrolment token {id}. List them with GET /console/devices/tokens."),
        ),
        Err((status, code, message)) => fail(status, code, &message),
    }
}

/// Forgets a device and its binding, recorded first: its next report binds it to whoever sends it.
async fn remove_device_api(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Response {
    if bearer(&headers).is_empty() && !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    let viewer = role_of(&admin) == Role::Viewer;
    let recorded = console
        .audit(
            Some(&admin),
            "device_removed",
            json!({ "device_id": id }),
            viewer.then_some("read_only"),
        )
        .await;
    if viewer {
        return fail(
            StatusCode::FORBIDDEN,
            "read_only",
            "Your role is viewer. An owner or admin can remove devices.",
        );
    }
    if let Err(e) = recorded {
        return fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", e);
    }
    // A device outside the role's reach is, to its holder, not there.
    let within = match d.devices(&admin).await {
        Ok(devices) => devices
            .iter()
            .any(|device| device["device_id"] == id.as_str()),
        Err(e) => return fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    };
    let removed = match d.db.client().await {
        Ok(_) if !within => Ok(0),
        Ok(client) => client
            .execute(
                "DELETE FROM enterprise_devices WHERE device_id = $1",
                &[&id],
            )
            .await
            .map_err(db_error),
        Err(e) => Err(e),
    };
    match removed {
        Ok(0) => fail(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("No device {id}. List them with GET /console/devices/devices.json."),
        ),
        Ok(_) => Json(json!({ "device_id": id, "status": "removed" })).into_response(),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

async fn list_mcp_api(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
) -> Response {
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    match d.mcp_servers(&admin).await {
        Ok(servers) => Json(json!({ "servers": servers })).into_response(),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

/// `{"transport": "http", "target": "https://mcp.example.com/mcp", "decision": "blocked"}`: approved, blocked, or
/// pending to take a decision back.
async fn decide_mcp_api(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if bearer(&headers).is_empty() && !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let text = |k: &str| body[k].as_str().unwrap_or("").trim().to_string();
    let (transport, target, decision) = (text("transport"), text("target"), text("decision"));
    match d
        .decide_mcp(&console, &admin, &transport, &target, &decision)
        .await
    {
        Ok(()) => Json(json!({ "transport": transport, "target": target, "decision": decision }))
            .into_response(),
        Err((status, code, message)) => fail(status, code, &message),
    }
}

async fn devices_json(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
) -> Response {
    let Some(admin) = api_admin(&console, &d.keys, &headers).await else {
        return not_admin();
    };
    match d.devices(&admin).await {
        Ok(devices) => (
            [(
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"devices.json\"",
            )],
            Json(Value::Array(devices)),
        )
            .into_response(),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

// ---------------------------------------------------------------- the console page

async fn page(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    show(&console, &d, &admin, &uri, "", false).await
}

async fn show(
    console: &Console,
    d: &Devices,
    admin: &Admin,
    uri: &Uri,
    notice: &str,
    error: bool,
) -> Response {
    match main(d, admin, notice, error).await {
        Ok(main) => console.page(StatusCode::OK, admin, NAV, uri, &main),
        Err(err) => console.page(
            StatusCode::SERVICE_UNAVAILABLE,
            admin,
            NAV,
            uri,
            &format!("{}{}", html::head(NAV, "", ""), banner(&err, true)),
        ),
    }
}

fn form(action: &str, inner: &str) -> String {
    format!(
        r#"<form method="post" action="/console/devices" class="g-stack">{}{inner}</form>"#,
        hidden("action", action)
    )
}

/// Per person: the tools their traffic came from, their enrolled devices, the tools set to go through Enterplace, and
/// a tag for each tool going direct, each denied app installed and each blocked MCP server still configured. Then
/// why each tool found that no documented file configures stays `installed`.
fn people(traffic: &coverage::Coverage, devices: &[Value]) -> String {
    #[derive(Default)]
    struct Person {
        team: String,
        seen: BTreeSet<String>,
        devices: usize,
        stale: usize,
        by_hand: BTreeSet<String>,
    }
    let mut people: BTreeMap<String, Person> = BTreeMap::new();
    for ((person, tool), row) in traffic {
        let p = people.entry(person.clone()).or_default();
        p.team.clone_from(&row.team);
        if row.requests > row.refused {
            p.seen.insert(tool.clone());
        }
    }
    let mut by_hand: BTreeMap<String, String> = BTreeMap::new();
    for device in devices {
        let p = people
            .entry(device["person"].as_str().unwrap_or("-").to_string())
            .or_default();
        if p.team.is_empty() || p.team == "-" {
            p.team = device["team"].as_str().unwrap_or("").to_string();
        }
        p.devices += 1;
        p.stale += usize::from(device["stale"].as_bool().unwrap_or(false));
        for t in device["tools"].as_array().into_iter().flatten() {
            if let (Some(tool), Some(note)) = (t["tool"].as_str(), t["note"].as_str()) {
                p.by_hand.insert(tool.to_string());
                by_hand.insert(tool.to_string(), note.to_string());
            }
        }
    }
    if people.is_empty() {
        return html::empty(
            "",
            "Nothing seen yet",
            "No request has reached Enterplace and no device has reported. Run the device agent with an enrolment token.",
            "",
        );
    }
    // The same sums `enterplace audit coverage --devices` prints.
    let reported: Vec<coverage::Device> =
        serde_json::from_value(Value::Array(devices.to_vec())).unwrap_or_default();
    let mut sums = coverage::people(&reported);
    let mut out = String::from(r#"<section class="g-list">"#);
    for (person, p) in people {
        let sum = sums.remove(&person).unwrap_or_default();
        let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
        let seen = if p.seen.is_empty() {
            "no traffic".to_string()
        } else {
            format!("seen: {}", join(&p.seen))
        };
        let mut meta = format!(
            "{} · {seen} · {} device{}",
            if p.team.is_empty() { "-" } else { &p.team },
            p.devices,
            if p.devices == 1 { "" } else { "s" }
        );
        if p.stale > 0 {
            meta += &format!(" · {} not seen in 24 hours", p.stale);
        }
        if !sum.enterplace.is_empty() {
            meta += &format!(" · set to Enterplace: {}", join(&sum.enterplace));
        }
        if !p.by_hand.is_empty() {
            meta += &format!(" · installed, set by hand: {}", join(&p.by_hand));
        }
        let mut end = String::new();
        for (word, set) in [
            ("direct", &sum.direct),
            ("denied app", &sum.denied_apps),
            ("blocked MCP", &sum.blocked_mcp),
        ] {
            for detail in set {
                end += &html::tag("", word, detail);
            }
        }
        out += &html::row(&esc(&person), &esc(&meta), &end, true);
    }
    out += "</section>";
    for (tool, note) in by_hand {
        out += &format!(
            r#"<p class="t-small g-muted" style="margin: 0">{}: {}</p>"#,
            esc(&tool),
            esc(&note)
        );
    }
    out
}

/// Each MCP server devices reported, with the tools and devices that have it, whether it goes through Enterplace's MCP
/// gateway, its decision, and the buttons that change it.
fn mcp_list(servers: &[Value], can_edit: bool) -> String {
    if servers.is_empty() {
        return r#"<p class="t-small g-muted" style="margin: 0">No device has reported an MCP server yet. The device agent lists those configured in Claude Desktop, Claude Code, Cursor, VS Code and Zed, and takes a blocked one out of those files when the profile says remove.</p>"#.into();
    }
    let mut out = String::from(r#"<section class="g-list">"#);
    for m in servers {
        let s = |k: &str| m[k].as_str().unwrap_or("").to_string();
        let devices = m["devices"].as_i64().unwrap_or(0);
        let mut meta = format!(
            "{} · {} · {} · {devices} device{} · {}",
            s("servers"),
            s("transport"),
            s("tools"),
            if devices == 1 { "" } else { "s" },
            if m["via_enterplace"] == true {
                "via Enterplace"
            } else {
                "not via Enterplace"
            }
        );
        if !s("decided_by").is_empty() {
            meta += &format!(
                " · {} by {} at {}",
                s("decision"),
                s("decided_by"),
                s("decided_at")
            );
        }
        let mut end = html::tag("", &esc(&s("decision")), "");
        if can_edit {
            for (decision, label) in [("approved", "Approve"), ("blocked", "Block")] {
                if s("decision") != decision {
                    end += &form(
                        "mcp_decide",
                        &format!(
                            "{}{}{}{}",
                            hidden("transport", &s("transport")),
                            hidden("target", &s("target")),
                            hidden("decision", decision),
                            small_button(label)
                        ),
                    );
                }
            }
        }
        out += &html::row(&esc(&s("target")), &esc(&meta), &end, true);
    }
    out + "</section>"
}

async fn main(d: &Devices, admin: &Admin, notice: &str, error: bool) -> Result<String, String> {
    let can_edit = role_of(admin) != Role::Viewer;
    let tokens = d.tokens(admin).await?;
    let devices = d.devices(admin).await?;
    let (traffic, profiles, drift, refusals, actions) = {
        let client = d.db.client().await?;
        // Every replica's requests, summed in the store's request index (the insights namespace every gateway
        // with a store keeps), not this replica's audit log read whole.
        let rows = client
            .query(
                &format!("SELECT coalesce(labels->'person'->>0, '-'), coalesce(labels->'agent'->>0, 'unknown'), min(coalesce(labels->'team'->>0, '-')), \
                 count(*), count(*) FILTER (WHERE verdict <> 'allow'), to_char(max(time) AT TIME ZONE 'UTC', {TIME}) FROM enterplace_requests GROUP BY 1, 2"),
                &[],
            )
            .await
            .map_err(db_error)?;
        let traffic: coverage::Coverage = rows
            .iter()
            .map(|r| {
                let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
                let count = |i| u64::try_from(r.try_get::<_, i64>(i).unwrap_or(0)).unwrap_or(0);
                (
                    (get(0), get(1)),
                    coverage::Row {
                        team: get(2),
                        requests: count(3),
                        refused: count(4),
                        last_seen: get(5),
                        ..coverage::Row::default()
                    },
                )
            })
            .collect();
        let refusals = client
            .query(
                &format!("SELECT to_char(at AT TIME ZONE 'UTC', {TIME}), device_id, person, reason FROM enterprise_device_refusals ORDER BY id DESC LIMIT 20"),
                &[],
            )
            .await
            .map_err(db_error)?;
        let profiles = client
            .query("SELECT team, gateway_url, tools, updated_by, apps_allowed, apps_denied, mcp_via_gateway, mcp_enforcement FROM enterprise_device_profiles ORDER BY team", &[])
            .await
            .map_err(db_error)?;
        let drift = client
            .query(
                &format!("SELECT to_char(at AT TIME ZONE 'UTC', {TIME}), person, tool, device_id FROM enterprise_device_drift ORDER BY id DESC LIMIT 20"),
                &[],
            )
            .await
            .map_err(db_error)?;
        let actions = client
            .query(
                &format!("SELECT to_char(at AT TIME ZONE 'UTC', {TIME}), person, tool, device_id, server, target, action FROM enterprise_device_mcp_actions ORDER BY id DESC LIMIT 20"),
                &[],
            )
            .await
            .map_err(db_error)?;
        (traffic, profiles, drift, refusals, actions)
    };
    // Someone whose role keeps them to part of the install is shown what belongs to the devices they may see.
    // ponytail: their people's traffic is cut to those with such a device, and the recent refusals and drift to
    // those among the install's last 20. Filter in the queries if a kept role needs the rest.
    let (traffic, profiles, drift, refusals, actions) = if admin.confined() {
        let mine = |row: &enterplace_server::sql::Row, i: usize| {
            let id = row.try_get::<_, String>(i).unwrap_or_default();
            devices.iter().any(|d| d["device_id"] == id.as_str())
        };
        let team = |row: &enterplace_server::sql::Row| {
            admin
                .teams
                .contains(&row.try_get::<_, String>(0).unwrap_or_default())
        };
        (
            traffic
                .into_iter()
                .filter(|((person, _), _)| devices.iter().any(|d| d["person"] == person.as_str()))
                .collect(),
            profiles.into_iter().filter(team).collect(),
            drift.into_iter().filter(|r| mine(r, 3)).collect(),
            refusals.into_iter().filter(|r| mine(r, 1)).collect(),
            actions.into_iter().filter(|r| mine(r, 3)).collect(),
        )
    } else {
        (traffic, profiles, drift, refusals, actions)
    };
    let mut out = html::head(
        NAV,
        "Each person's coding tools: which reached Enterplace, which devices are enrolled, which tools there call a provider directly, and which denied apps and blocked MCP servers are on them. The device agent points the tools a profile names at the gateway, puts them back when someone changes them, and reports blocked MCP servers, or takes them out of the tools' MCP files when the profile says remove.",
        &html::link(
            "Download devices.json",
            "quiet",
            "/console/devices/devices.json",
            true,
        ),
    );
    if !notice.is_empty() {
        out += &banner(notice, error);
    }
    if devices.is_empty() {
        out += &enterplace_console::empty_page(
            "Devices",
            &enterplace_console::request_base(),
            can_edit,
        );
    }
    out += &section("Coverage", &people(&traffic, &devices));
    out += &section(
        "MCP servers: approve or block what devices are configured with",
        &mcp_list(&d.mcp_servers(admin).await?, can_edit),
    );

    let mut list = String::from(r#"<section class="g-list">"#);
    for t in &tokens {
        let s = |k: &str| t[k].as_str().unwrap_or("").to_string();
        let end = if can_edit && s("status") == "active" {
            form(
                "token_revoke",
                &format!("{}{}", hidden("id", &s("id")), small_button("Revoke token")),
            )
        } else {
            html::tag("", &esc(&s("status")), "")
        };
        let team = match s("team") {
            t if t.is_empty() => "every team".to_string(),
            t => format!("team {t}"),
        };
        list += &html::row(
            &esc(&s("label")),
            &esc(&format!(
                "{team} · expires {} · created by {}",
                s("expires_at"),
                s("created_by")
            )),
            &end,
            false,
        );
    }
    list += "</section>";
    if can_edit {
        list += r#"<span id="add-token"></span>"#;
        list += &form(
            "token_create",
            &format!(
                "{}{}{}{}",
                input(
                    "label",
                    "Label",
                    "",
                    " required",
                    "Where it is used, such as jamf-engineering."
                ),
                input(
                    "team",
                    "Team",
                    "",
                    "",
                    "Leave empty for every team; a team token enrols devices into that team."
                ),
                input(
                    "days",
                    "Days valid",
                    &DEFAULT_DAYS.to_string(),
                    "",
                    &format!("1 to {MAX_DAYS}.")
                ),
                html::button("Create enrolment token", "", "submit", ""),
            ),
        );
    }
    out += &section("Enrolment tokens", &list);

    let mut list = String::from(r#"<section class="g-list">"#);
    for r in &profiles {
        let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
        let team = match get(0) {
            t if t.is_empty() => "Every team".to_string(),
            t => format!("Team {t}"),
        };
        let mut meta = format!("{} · manages {}", get(1), get(2).replace(',', ", "));
        for (word, apps) in [("allows", get(4)), ("denies", get(5))] {
            if !apps.is_empty() {
                meta += &format!(" · {word} {}", apps.replace(',', ", "));
            }
        }
        if r.try_get::<_, bool>(6).unwrap_or(false) {
            meta += " · approved MCP servers go through Enterplace";
        }
        if get(7) == "remove" {
            meta += " · removes blocked MCP servers";
        }
        meta += &format!(" · by {}", get(3));
        list += &html::row(&esc(&team), &esc(&meta), "", false);
    }
    list += "</section>";
    if can_edit {
        list += &form(
            "profile_save",
            &format!(
                "{}{}{}{}{}{}{}{}",
                input(
                    "team",
                    "Team",
                    "",
                    "",
                    "Empty for every team without its own profile."
                ),
                input(
                    "gateway_url",
                    "Gateway URL",
                    "",
                    " required",
                    "The address tools send requests to, without /v1."
                ),
                input(
                    "tools",
                    "Tools to manage",
                    &DEFAULT_MANAGED.join(", "),
                    "",
                    &format!("Any of {}, comma separated.", MANAGEABLE.join(", "))
                ),
                input(
                    "apps_denied",
                    "Denied apps",
                    "",
                    "",
                    &format!(
                        "Reported where installed, never stopped. Any of {}, comma separated.",
                        app_names().join(", ")
                    )
                ),
                input(
                    "apps_allowed",
                    "Allowed apps",
                    "",
                    "",
                    "Empty for no allow list. With one, every other app above counts as denied."
                ),
                input(
                    "mcp_via_gateway",
                    "Approved MCP servers through Enterplace",
                    "no",
                    "",
                    "yes or no. With yes, the agent points each approved HTTP server at this gateway's /mcp: list those servers under mcp: in the policy first."
                ),
                input(
                    "mcp_enforcement",
                    "Blocked MCP servers",
                    "report",
                    "",
                    "report or remove. With report, the agent lists a blocked server it finds; with remove, it takes it out of the tool's file and keeps the file as it was beside it."
                ),
                html::button("Save device profile", "", "submit", ""),
            ),
        );
    }
    out += &section("Device profiles", &list);

    let mut list = String::from(r#"<section class="g-list">"#);
    for r in &drift {
        let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
        list += &html::row(
            &esc(&get(1)),
            &esc(&format!("{} · {}", get(2), get(0))),
            "",
            true,
        );
    }
    if drift.is_empty() {
        list += r#"<p class="t-small g-muted" style="margin: 0">No drift. Nobody changed a managed setting back.</p>"#;
    }
    list += "</section>";
    out += &section("Drift: settings changed back and re-applied", &list);

    let mut list = String::from(r#"<section class="g-list">"#);
    for r in &actions {
        let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
        list += &html::row(
            &esc(&get(1)),
            &esc(&format!(
                "{} · {} ({}) in {} · {} · {}",
                get(6),
                get(4),
                get(5),
                get(2),
                get(3),
                get(0)
            )),
            "",
            true,
        );
    }
    if actions.is_empty() {
        list += r#"<p class="t-small g-muted" style="margin: 0">Nothing enforced yet. With a profile that says remove, the agent takes a blocked server out of a tool's MCP file and keeps the file as it was beside it.</p>"#;
    }
    list += "</section>";
    out += &section(
        "MCP enforcement: servers removed or sent through Enterplace",
        &list,
    );

    let mut list = String::from(r#"<section class="g-list">"#);
    for r in &refusals {
        let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
        list += &html::row(
            &esc(&get(1)),
            &esc(&format!("{} · {} · {}", get(2), get(3), get(0))),
            "",
            true,
        );
    }
    if refusals.is_empty() {
        list += r#"<p class="t-small g-muted" style="margin: 0">No refused reports. Every device reported as the person and token scope it is bound to.</p>"#;
    }
    list += "</section>";
    out += &section("Refused reports: another person or token scope", &list);
    Ok(out)
}

async fn act(
    State(console): State<Console>,
    Ext(d): Ext<Devices>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign().into_response();
    }
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    match form.get("action") {
        "token_create" => {
            let days = form.get("days").trim().parse().unwrap_or(0);
            match d
                .create(
                    &console,
                    &admin,
                    form.get("label"),
                    form.get("team"),
                    "",
                    days,
                )
                .await
            {
                Ok((_, token, expires)) => {
                    let main = format!(
                        r#"{}<span class="g-command g-command--value"><span class="g-command__text t-mono" id="shown-once">{}</span><button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="shown-once">{}Copy</button></span><div class="g-head__actions">{}</div>"#,
                        html::head(
                            "Enrolment token created",
                            &esc(&format!(
                                "Valid until {expires}. Put it in your MDM now, never in chat: Enterplace keeps only its hash and cannot show it again."
                            )),
                            ""
                        ),
                        esc(&token),
                        html::icon("copy"),
                        html::link("Done", "", "/console/devices", false)
                    );
                    console.page(StatusCode::OK, &admin, NAV, &uri, &main)
                }
                Err((_, _, message)) => show(&console, &d, &admin, &uri, &message, true).await,
            }
        }
        "token_revoke" => {
            let (notice, error) = match d.revoke(&console, &admin, form.get("id").trim()).await {
                Ok(true) => (
                    "Token revoked. Devices using it are refused from their next check."
                        .to_string(),
                    false,
                ),
                Ok(false) => ("That token is already revoked.".to_string(), true),
                Err((_, _, message)) => (message, true),
            };
            show(&console, &d, &admin, &uri, &notice, error).await
        }
        "mcp_decide" => {
            let decision = form.get("decision").trim();
            let (notice, error) = match d
                .decide_mcp(
                    &console,
                    &admin,
                    form.get("transport").trim(),
                    form.get("target").trim(),
                    decision,
                )
                .await
            {
                Ok(()) => (
                    format!(
                        "MCP server {} {decision}. Devices pick it up on their next check.",
                        form.get("target").trim()
                    ),
                    false,
                ),
                Err((_, _, message)) => (message, true),
            };
            show(&console, &d, &admin, &uri, &notice, error).await
        }
        "profile_save" => {
            let (notice, error) = match save_profile(&console, &d, &admin, &form).await {
                Ok(notice) => (notice, false),
                Err(message) => (message, true),
            };
            show(&console, &d, &admin, &uri, &notice, error).await
        }
        _ => {
            show(
                &console,
                &d,
                &admin,
                &uri,
                "Unknown action. Use the buttons on this page.",
                true,
            )
            .await
        }
    }
}

async fn save_profile(
    console: &Console,
    d: &Devices,
    admin: &Admin,
    form: &Form,
) -> Result<String, String> {
    let action = "device_profile_saved";
    let team = form.get("team").trim().to_string();
    let gateway = form
        .get("gateway_url")
        .trim()
        .trim_end_matches('/')
        .to_string();
    let tools = names(form.get("tools"));
    let (allowed, denied) = (
        names(form.get("apps_allowed")),
        names(form.get("apps_denied")),
    );
    let via_gateway = match form.get("mcp_via_gateway").trim() {
        "" | "no" => Some(false),
        "yes" => Some(true),
        _ => None,
    };
    let enforcement = match form.get("mcp_enforcement").trim() {
        "" | "report" => Some("report"),
        "remove" => Some("remove"),
        _ => None,
    };
    let known_apps = app_names();
    let problem = if role_of(admin) == Role::Viewer {
        Some((
            "read_only",
            "Your role is viewer. An owner or admin can change device profiles.".to_string(),
        ))
    } else if !team.is_empty() && !config::valid_name(&team) {
        Some((
            "invalid_request",
            format!("{team:?} is not a team name: use letters, digits, dot, dash or underscore."),
        ))
    } else if !valid_gateway(&gateway) {
        Some(("invalid_request", "The gateway URL is an https address without a query, such as https://enterplace.example.com.".to_string()))
    } else if let Some(t) = tools.iter().find(|t| !MANAGEABLE.contains(&t.as_str())) {
        Some((
            "invalid_request",
            match why_not(t) {
                Some(why) => format!("The agent cannot configure {t:?}: {why}"),
                None => format!(
                    "The agent cannot configure {t:?}. Tools it manages: {}.",
                    MANAGEABLE.join(", ")
                ),
            },
        ))
    } else if let Some(app) = allowed
        .iter()
        .chain(&denied)
        .find(|a| !known_apps.contains(&a.as_str()))
    {
        Some((
            "invalid_request",
            format!(
                "{app:?} is not an app the agent looks for. Apps it knows: {}.",
                known_apps.join(", ")
            ),
        ))
    } else if let Some(app) = allowed.iter().find(|a| denied.contains(a)) {
        Some((
            "invalid_request",
            format!("{app:?} is both allowed and denied. List it under one."),
        ))
    } else if via_gateway.is_none() {
        Some((
            "invalid_request",
            "Approved MCP servers through Enterplace is yes or no.".to_string(),
        ))
    } else if enforcement.is_none() {
        Some((
            "invalid_request",
            "Blocked MCP servers is report or remove.".to_string(),
        ))
    } else {
        None
    };
    let via_gateway = via_gateway.unwrap_or(false);
    let enforcement = enforcement.unwrap_or("report");
    let details = json!({
        "team": team, "gateway_url": gateway, "tools": tools,
        "apps_allowed": allowed, "apps_denied": denied, "mcp_via_gateway": via_gateway,
        "mcp_enforcement": enforcement,
    });
    if let Some((code, message)) = problem {
        let _ = console
            .audit(Some(admin), action, details, Some(code))
            .await;
        return Err(message);
    }
    console
        .audit(Some(admin), action, details, None)
        .await
        .map_err(str::to_string)?;
    let client = d.db.client().await?;
    client
        .execute(
            "INSERT INTO enterprise_device_profiles (team, gateway_url, tools, updated_by, apps_allowed, apps_denied, mcp_via_gateway, mcp_enforcement) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (team) DO UPDATE SET gateway_url = excluded.gateway_url, tools = excluded.tools, updated_by = excluded.updated_by, \
             apps_allowed = excluded.apps_allowed, apps_denied = excluded.apps_denied, mcp_via_gateway = excluded.mcp_via_gateway, mcp_enforcement = excluded.mcp_enforcement, updated_at = now()",
            &[&team, &gateway, &tools.join(","), &admin.name, &allowed.join(","), &denied.join(","), &via_gateway, &enforcement],
        )
        .await
        .map_err(db_error)?;
    Ok(format!(
        "Device profile for {} saved. Devices pick it up on their next check.",
        if team.is_empty() {
            "every team".to_string()
        } else {
            format!("team {team}")
        }
    ))
}
