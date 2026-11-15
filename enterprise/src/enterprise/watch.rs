//! Watch mode (license feature `watch`): what Claude Code reports about itself, for people on Claude Team and
//! Enterprise seats, whose requests cannot go through a gateway. Claude Code's own OpenTelemetry export is received
//! at `/otlp/v1/metrics` and `/otlp/v1/logs`, authenticated by a watch token, and becomes `watch` records in the
//! audit chain plus daily sums in Postgres. Gantry sees; it does not block or budget, because nothing passes it.
//!
//! Ported from the Cloudflare app's claude.ts. What the port adds: protobuf, tokens that expire and belong to a
//! team or a person, exports counted once, cumulative metrics, audit records, and retention. It never reads prompt,
//! answer or tool text, even when Claude Code is told to send it: only the fields named here are copied.

mod otlp;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    Extension as Ext, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as UrlPath, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use gantry_console::{Admin, Console, foreign, same_origin};
use gantry_core::{audit, config, id::sha256_hex};
use serde_json::{Map, Value, json};

use self::otlp::{Attrs, Event, Point};
use super::Db;
use super::devices::{Json, api_admin, bearer, fail, not_admin, outside, token_org};
use super::siem::{Role, db_error, random_hex, role_of};
use crate::license::Status;
use gantry_server::store::tokio_postgres::Client;

pub const FEATURE: &str = "watch";

pub const MIGRATION: &str = "
CREATE TABLE enterprise_watch_tokens (
    id text PRIMARY KEY,
    label text NOT NULL,
    person text NOT NULL DEFAULT '',
    team text NOT NULL DEFAULT '',
    token_sha256 text NOT NULL UNIQUE,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_used timestamptz
);
CREATE TABLE enterprise_watch_seen (
    key text PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_watch_series (
    key text PRIMARY KEY,
    time_ns bigint NOT NULL,
    value double precision NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_watch_daily (
    day date NOT NULL,
    person text NOT NULL,
    team text NOT NULL DEFAULT '',
    metric text NOT NULL,
    label text NOT NULL DEFAULT '',
    value double precision NOT NULL,
    PRIMARY KEY (day, person, metric, label)
);
";

/// The organization a token's records belong to, for installs with `orgs:`. Empty for none.
pub const MIGRATION_2: &str = "
ALTER TABLE enterprise_watch_tokens ADD COLUMN org text NOT NULL DEFAULT '';
";

/// The organization of the token a day's sums came in with, so an admin kept to one organization is shown its
/// sums alone. Sums from before this are the install's (no organization).
pub const MIGRATION_3: &str = "
ALTER TABLE enterprise_watch_daily ADD COLUMN org text NOT NULL DEFAULT '';
";

pub const PREFIX: &str = "gantry_watch_";
const DEFAULT_DAYS: i32 = 90;
const MAX_DAYS: i32 = 365;
/// The largest export taken. Claude Code batches at most a few hundred records an export.
const MAX_BODY: usize = 4 * 1024 * 1024;
/// How long the watch tables are kept on an install without the retention feature's setting.
const KEEP_DAYS: i32 = 365;
/// An export is retried within minutes, so what tells a repeat apart is kept a week.
const REPEAT_DAYS: i32 = 7;
const PRUNE_EVERY: Duration = Duration::from_secs(3600);
const TIME: &str = r#"'YYYY-MM-DD"T"HH24:MI:SS"Z"'"#;
/// The events that become records. Every other event Claude Code sends (plugins, hooks, settings) is dropped.
const KEPT: [&str; 6] = [
    "api_request",
    "api_error",
    "api_refusal",
    "tool_decision",
    "tool_result",
    "user_prompt",
];
/// Attributes that hold what a person or the model wrote. Never copied anywhere; an event that has one is counted.
const CONTENT: [&str; 6] = [
    "prompt",
    "prompt_text",
    "response",
    "tool_input",
    "tool_parameters",
    "body",
];
pub const NEEDS_TRAFFIC: &str = "needs API traffic through Gantry";

#[derive(Clone)]
struct Watch {
    db: Arc<Db>,
    keys: PathBuf,
    log: Arc<audit::AuditLog>,
    policy: gantry_server::PolicyNow,
    pruned: Arc<Mutex<Option<Instant>>>,
}

/// Adds the OTLP receiver and the console's watch API.
pub fn register(
    extension: &mut gantry_server::Extension,
    db: Arc<Db>,
    keys: PathBuf,
    log: Arc<audit::AuditLog>,
    policy: gantry_server::PolicyNow,
) {
    let watch = Watch {
        db,
        keys,
        log,
        policy,
        pruned: Arc::default(),
    };
    let receiver = Router::new()
        .route("/otlp/v1/metrics", post(metrics))
        .route("/otlp/v1/logs", post(logs))
        // One over the limit, so the handler answers a larger export with the fix instead of axum's bare 413.
        .layer(DefaultBodyLimit::max(MAX_BODY + 1))
        .layer(Ext(watch.clone()));
    extension.routes = std::mem::take(&mut extension.routes).merge(receiver);
    let console = &mut extension.console;
    console.nav.push(("/console/watch".into(), NAV.into()));
    // Start here makes and counts watch tokens through the same checks and records as the API.
    let (made, counted) = (watch.clone(), watch.clone());
    console.watch = Some(gantry_console::Watch {
        token: Arc::new(move |console: Console, admin: Admin, team: String| {
            let w = made.clone();
            Box::pin(async move {
                let label = format!(
                    "claude-team-{}",
                    if team.is_empty() { "all" } else { &team }
                );
                w.create(&console, &admin, &json!({ "label": label, "team": team }))
                    .await
                    .map(|(_, token, _)| token)
                    .map_err(|(_, _, message)| message)
            })
        }),
        tokens: Arc::new(move |admin: Admin| {
            let w = counted.clone();
            Box::pin(async move { w.tokens(&admin).await.map(|t| t.len()) })
        }),
    });
    console.routes = std::mem::take(&mut console.routes)
        .route("/watch", get(page))
        .route("/watch/tokens", get(list_tokens).post(create_token))
        .route("/watch/tokens/{id}", delete(revoke_token))
        .route("/watch/summary.json", get(summary))
        .layer(Ext(watch));
}

const NAV: &str = "Watch";

/// The Watch page: each watched person over the last 30 days, or what fills it.
async fn page(
    State(console): State<Console>,
    Ext(w): Ext<Watch>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return gantry_console::redirect("/console/sign-in");
    };
    let head = gantry_console::html::head(
        NAV,
        "Claude Code on Claude Team and Enterprise seats, from its own telemetry. Nothing is routed: costs are Claude Code's estimates at list price.",
        "",
    );
    let main = match w.summary(&admin, 30).await {
        Err(err) => format!(
            "{head}{}",
            gantry_console::html::empty(
                "",
                "Watch did not load",
                &gantry_console::html::esc(&format!(
                    "{err}. Check the store, then open the page again."
                )),
                "",
            )
        ),
        Ok(summary) => {
            let people = summary["people"].as_array().cloned().unwrap_or_default();
            if people.is_empty() {
                format!(
                    "{head}{}",
                    gantry_console::empty_page(
                        NAV,
                        &gantry_console::request_base(),
                        role_of(&admin) != Role::Viewer
                    )
                )
            } else {
                let esc = gantry_console::html::esc;
                let rows: String = people
                    .iter()
                    .map(|p| {
                        let m = &p["metrics"];
                        let n = |k: &str| m[k].as_f64().unwrap_or(0.0);
                        format!(
                            r#"<tr><td class="t-mono-sm">{}</td><td class="t-mono-sm g-table__wide">{}</td><td class="t-mono-sm g-table__num">{}</td><td class="t-mono-sm g-table__num g-table__wide">{}</td><td class="t-mono-sm g-table__num">${:.2}</td><td class="t-mono-sm g-table__wide">{}</td></tr>"#,
                            esc(p["person"].as_str().unwrap_or("")),
                            esc(p["team"].as_str().unwrap_or("")),
                            n("sessions"),
                            n("tokens_input") + n("tokens_output"),
                            n("cost_usd"),
                            esc(p["last_day"].as_str().unwrap_or("")),
                        )
                    })
                    .collect();
                format!(
                    r#"{head}<section class="g-panel"><div class="g-table-wrap"><table class="g-table g-table--stack"><thead><tr><th class="t-tag">Person</th><th class="t-tag g-table__wide">Team</th><th class="t-tag g-table__num">Sessions</th><th class="t-tag g-table__num g-table__wide">Tokens</th><th class="t-tag g-table__num">Estimated cost</th><th class="t-tag g-table__wide">Last day</th></tr></thead><tbody>{rows}</tbody></table></div></section>"#
                )
            }
        }
    };
    console.page(StatusCode::OK, &admin, NAV, &uri, &main)
}

/// Without the feature the receiver and the API say why.
pub fn locked(extension: &mut gantry_server::Extension, status: &Status) {
    let Err(refused) = status.require(FEATURE) else {
        return;
    };
    let (code, message) = (refused.code, refused.message);
    let api = move || {
        let message = message.clone();
        async move { fail(StatusCode::FORBIDDEN, code, &message) }
    };
    extension.routes = std::mem::take(&mut extension.routes).merge(
        Router::new()
            .route("/otlp/v1/metrics", post(api.clone()))
            .route("/otlp/v1/logs", post(api.clone())),
    );
    let console = &mut extension.console;
    console.routes = std::mem::take(&mut console.routes)
        .route("/watch/tokens", get(api.clone()).post(api.clone()))
        .route("/watch/summary.json", get(api));
}

type Refusal = (StatusCode, &'static str, String);

fn unavailable(err: String) -> Refusal {
    (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", err)
}

fn refuse((status, code, message): Refusal) -> Response {
    fail(status, code, &message)
}

/// Who an export is from, as its token says.
struct Token {
    id: String,
    person: String,
    team: String,
    org: String,
}

/// Who the install knows, to give the email Claude Code reports the name that person's gateway traffic has.
#[derive(Default)]
struct People {
    /// Each key's name, and the `email` of its `metadata:` in lower case.
    keys: Vec<(String, Option<String>)>,
    /// Lower case: the policy's team owners and members (the people single sign-on lets in), and the members
    /// feature's people, SCIM's among them.
    emails: std::collections::HashSet<String>,
}

impl People {
    /// The name `reported` goes by and whether the install knows them: the holder of a key whose metadata has that
    /// email, else of a key named by it (as single sign-on names keys), else the email itself.
    fn name(&self, reported: &str) -> (String, bool) {
        let lower = reported.to_lowercase();
        let by_email = self
            .keys
            .iter()
            .find(|(_, email)| email.as_deref() == Some(lower.as_str()));
        let by_name = || {
            self.keys
                .iter()
                .find(|(name, _)| name.to_lowercase() == lower)
        };
        match by_email.or_else(by_name) {
            Some((name, _)) => (name.clone(), true),
            None => (reported.to_string(), self.emails.contains(&lower)),
        }
    }
}

// ---------------------------------------------------------------- reading an export

fn text(attrs: &Attrs, key: &str, max: usize) -> Option<String> {
    let value = match attrs.get(key)? {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    };
    Some(value.chars().take(max).collect::<String>()).filter(|v| !v.is_empty())
}

/// A count or an amount: Claude Code writes some as numbers and some (`prompt_length`) as text.
fn number(attrs: &Attrs, key: &str) -> Option<f64> {
    match attrs.get(key)? {
        Value::String(s) => s.parse().ok(),
        v => v.as_f64(),
    }
    .filter(|n: &f64| n.is_finite() && *n >= 0.0)
}

fn whole(attrs: &Attrs, key: &str) -> Option<u64> {
    number(attrs, key).map(|n| n as u64)
}

/// When a point or event happened, as records write time. A time the sender's clock got badly wrong (none, before
/// 2001, or more than a day ahead) is now.
fn at(time_ns: u64) -> String {
    let now = SystemTime::now();
    let then = UNIX_EPOCH + Duration::from_nanos(time_ns);
    let sane = time_ns > 1_000_000_000_000_000_000 && then < now + Duration::from_secs(86_400);
    audit::rfc3339(if sane { then } else { now })
}

impl Token {
    /// The person an export is about: the token's when it is one person's, else the address Claude Code signed in
    /// with. Without either (an API key and no `OTEL_RESOURCE_ATTRIBUTES=user.email=...`) it is `unknown`.
    fn reported(&self, attrs: &Attrs) -> String {
        if !self.person.is_empty() {
            return self.person.clone();
        }
        text(attrs, "user.email", 200).map_or_else(|| "unknown".into(), |e| e.to_lowercase())
    }
}

/// The daily sum a metric point adds to, and its label (the model or the tool).
fn metric_of(point: &Point) -> Option<(&'static str, String)> {
    let kind = text(&point.attrs, "type", 20).unwrap_or_default();
    let model = || text(&point.attrs, "model", 80).unwrap_or_default();
    let name = point
        .metric
        .strip_prefix("claude_code.")
        .unwrap_or(&point.metric);
    Some(match name {
        "cost.usage" => ("cost_usd", model()),
        "token.usage" => (
            match kind.as_str() {
                "input" => "tokens_input",
                "output" => "tokens_output",
                "cacheRead" => "tokens_cache_read",
                "cacheCreation" => "tokens_cache_creation",
                _ => return None,
            },
            model(),
        ),
        "lines_of_code.count" => (
            match kind.as_str() {
                "added" => "lines_added",
                "removed" => "lines_removed",
                _ => return None,
            },
            String::new(),
        ),
        "commit.count" => ("commits", String::new()),
        "pull_request.count" => ("pull_requests", String::new()),
        "session.count" => ("sessions", String::new()),
        "active_time.total" => ("active_seconds", String::new()),
        "code_edit_tool.decision" => (
            match text(&point.attrs, "decision", 20).as_deref() {
                Some("accept") => "edits_accepted",
                Some("reject") => "edits_rejected",
                _ => return None,
            },
            text(&point.attrs, "tool_name", 80).unwrap_or_default(),
        ),
        _ => return None,
    })
}

/// What one export adds once repeats are taken out: sums per (day, person, team, metric, label), and records.
#[derive(Default)]
struct Added {
    daily: BTreeMap<(String, String, String, &'static str, String), f64>,
    records: Vec<Map<String, Value>>,
}

impl Added {
    fn add(
        &mut self,
        day: &str,
        person: &str,
        team: &str,
        metric: &'static str,
        label: &str,
        value: f64,
    ) {
        *self
            .daily
            .entry((day.into(), person.into(), team.into(), metric, label.into()))
            .or_default() += value;
    }
}

/// The fields every watch record starts with.
fn record(
    token: &Token,
    kind: &str,
    person: &str,
    attrs: &Attrs,
    time_ns: u64,
) -> Map<String, Value> {
    let version = text(attrs, "app.version", 40).or_else(|| text(attrs, "service.version", 40));
    // Bedrock and the other clouds name themselves; Anthropic's own API is `firstParty`.
    let provider = text(attrs, "anthropic.provider", 40)
        .filter(|p| p != "firstParty")
        .unwrap_or_else(|| "anthropic".into());
    let mut r = Map::new();
    r.insert("event".into(), "watch".into());
    r.insert("id".into(), gantry_core::id::decision_id().into());
    r.insert("time".into(), audit::timestamp().into());
    r.insert("source".into(), "watch".into());
    r.insert("kind".into(), kind.into());
    r.insert("at".into(), at(time_ns).into());
    r.insert("person".into(), person.into());
    r.insert(
        "team".into(),
        Some(&token.team)
            .filter(|t| !t.is_empty())
            .map_or(Value::Null, |t| t.as_str().into()),
    );
    // With `audit: { per_org: true }` the audit log sends a record that names its organization to that chain.
    if !token.org.is_empty() {
        r.insert("org".into(), token.org.as_str().into());
    }
    r.insert("token".into(), token.id.as_str().into());
    r.insert("session".into(), text(attrs, "session.id", 80).into());
    r.insert(
        "user_agent".into(),
        format!("claude-code/{}", version.as_deref().unwrap_or("unknown")).into(),
    );
    r.insert("provider".into(), provider.into());
    r
}

/// One kept event as its record and the daily sums it adds to. `None` for an event that is not kept.
fn event_record(
    token: &Token,
    event: &Event,
    name: &str,
    person: &str,
    added: &mut Added,
) -> Option<Map<String, Value>> {
    let a = &event.attrs;
    let day = at(event.time_ns).get(..10).unwrap_or_default().to_string();
    let mut count =
        |metric, label: &str, value| added.add(&day, person, &token.team, metric, label, value);
    let mut r = record(token, name, person, a, event.time_ns);
    let tool = text(a, "tool_name", 80).unwrap_or_default();
    let mut put = |field: &str, value: Value| {
        if !value.is_null() {
            r.insert(field.into(), value);
        }
    };
    match name {
        "api_request" | "api_error" | "api_refusal" => {
            put("model", text(a, "model", 80).into());
            put("latency_ms", whole(a, "duration_ms").into());
            match name {
                "api_request" => {
                    put("input_tokens", whole(a, "input_tokens").into());
                    put("output_tokens", whole(a, "output_tokens").into());
                    put("cache_read_tokens", whole(a, "cache_read_tokens").into());
                    put(
                        "cache_write_tokens",
                        whole(a, "cache_creation_tokens").into(),
                    );
                    put("cost_usd", number(a, "cost_usd").into());
                    count("api_requests", "", 1.0);
                }
                "api_error" => {
                    put("status", whole(a, "status_code").into());
                    // The API's error name, such as `overloaded`: not something a person wrote.
                    put("error", text(a, "error", 120).into());
                    count("api_errors", "", 1.0);
                }
                _ => count("api_refusals", "", 1.0),
            }
        }
        "tool_decision" => {
            let decision = text(a, "decision", 20).unwrap_or_default();
            put("tool", tool.as_str().into());
            put("decision", decision.as_str().into());
            put("decision_source", text(a, "source", 40).into());
            match decision.as_str() {
                "accept" => count("tool_accepted", &tool, 1.0),
                "reject" => count("tool_rejected", &tool, 1.0),
                _ => {}
            }
        }
        "tool_result" => {
            let ok = text(a, "success", 10).is_none_or(|s| s == "true");
            put("tool", tool.as_str().into());
            put("success", ok.into());
            put("latency_ms", whole(a, "duration_ms").into());
            count("tool_runs", &tool, 1.0);
            if !ok {
                count("tool_failures", &tool, 1.0);
            }
        }
        "user_prompt" => {
            let length = whole(a, "prompt_length");
            put("prompt_length", length.into());
            count("prompts", "", 1.0);
            count("prompt_chars", "", length.unwrap_or(0) as f64);
        }
        _ => return None,
    }
    Some(r)
}

impl Watch {
    /// The watch token an export came with, if it is one that works now.
    async fn token(&self, headers: &HeaderMap) -> Result<Token, Refusal> {
        let token = bearer(headers);
        let invalid = || {
            (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Send a watch token as OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer gantry_watch_... in Claude Code's managed settings. An owner or admin creates one with `gantry watch setup`; a revoked token stops working.".to_string(),
            )
        };
        if !token.starts_with(PREFIX) {
            return Err(invalid());
        }
        let client = self.db.client().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                &format!(
                    "UPDATE enterprise_watch_tokens SET last_used = CASE WHEN expires_at < now() THEN last_used ELSE now() END \
                     WHERE token_sha256 = $1 AND revoked_at IS NULL \
                     RETURNING id, person, team, expires_at < now(), to_char(expires_at AT TIME ZONE 'UTC', {TIME}), org"
                ),
                &[&sha256_hex(token.as_bytes())],
            )
            .await
            .map_err(|e| unavailable(db_error(e)))?
            .ok_or_else(invalid)?;
        let get = |i| row.try_get::<_, String>(i).unwrap_or_default();
        if row.try_get::<_, bool>(3).unwrap_or(true) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "token_expired",
                format!(
                    "This watch token expired at {}. Create a new one with `gantry watch setup` and put its settings in place of the old.",
                    get(4)
                ),
            ));
        }
        Ok(Token {
            id: get(0),
            person: get(1),
            team: get(2),
            org: get(5),
        })
    }

    /// The people the install knows now: key holders, the policy's teams, and members.
    async fn people(&self, client: &Client) -> Result<People, String> {
        let mut people = People::default();
        if let Ok(Some(text)) = config::read_keys(&self.keys) {
            for entry in config::key_entries(&self.keys, &text).unwrap_or_default() {
                let email = entry
                    .options
                    .metadata
                    .get("email")
                    .map(|e| e.to_lowercase());
                people.keys.push((entry.name, email));
            }
        }
        self.policy.with(|policy| {
            for team in policy.teams() {
                people
                    .emails
                    .extend(team.owner.iter().chain(&team.members).cloned());
            }
        });
        // The members feature's table, when the install has it.
        let has: bool = client
            .query_one("SELECT to_regclass('enterprise_people') IS NOT NULL", &[])
            .await
            .and_then(|r| r.try_get(0))
            .map_err(db_error)?;
        if has {
            let rows = client
                .query("SELECT lower(email) FROM enterprise_people", &[])
                .await
                .map_err(db_error)?;
            people
                .emails
                .extend(rows.iter().filter_map(|r| r.try_get(0).ok()));
        }
        Ok(people)
    }

    /// Stores what an export adds and writes its records, all or nothing: on an error Claude Code sends it again,
    /// and what was already taken is told apart as a repeat.
    async fn keep(
        &self,
        token: &Token,
        points: Vec<Point>,
        events: Vec<Event>,
    ) -> Result<(), Refusal> {
        let failed = |e| unavailable(db_error(e));
        let mut added = Added::default();
        let mut client = self.db.client().await.map_err(unavailable)?;
        let people = self.people(&client).await.map_err(unavailable)?;
        // A token of one person names them itself. Otherwise the email Claude Code reports becomes the name the
        // install knows that person by, so their watched and gateway traffic are one person's.
        let named = |reported: &str| {
            if token.person.is_empty() {
                people.name(reported).0
            } else {
                reported.to_string()
            }
        };
        let tx = client.transaction().await.map_err(failed)?;

        // Events: each taken once. The key is who and when, with the sequence Claude Code numbers its events by.
        let mut candidates = Vec::new();
        for event in &events {
            let a = &event.attrs;
            let name = text(a, "event.name", 60).unwrap_or_else(|| event.body.clone());
            let name = name
                .strip_prefix("claude_code.")
                .unwrap_or(&name)
                .to_string();
            // Repeats are told apart by who Claude Code said it was: a name given later does not make one new.
            let reported = token.reported(a);
            let person = named(&reported);
            let said = CONTENT
                .iter()
                .any(|c| text(a, c, 20).is_some_and(|v| v != "<REDACTED>"));
            let key = sha256_hex(
                format!(
                    "{reported}\0{}\0{name}\0{}\0{}\0{}",
                    text(a, "session.id", 80).unwrap_or_default(),
                    text(a, "event.sequence", 20).unwrap_or_default(),
                    text(a, "event.timestamp", 40).unwrap_or_default(),
                    event.time_ns
                )
                .as_bytes(),
            );
            if said || KEPT.contains(&name.as_str()) {
                candidates.push((key, event, name, person, reported, said));
            }
        }
        let keys: Vec<&str> = candidates.iter().map(|c| c.0.as_str()).collect();
        let fresh: std::collections::HashSet<String> = tx
            .query(
                "INSERT INTO enterprise_watch_seen (key) SELECT DISTINCT unnest($1::text[]) ON CONFLICT DO NOTHING RETURNING key",
                &[&keys],
            )
            .await
            .map_err(failed)?
            .iter()
            .filter_map(|r| r.try_get(0).ok())
            .collect();
        for (key, event, name, person, reported, said) in &candidates {
            if !fresh.contains(key) {
                continue;
            }
            let day = at(event.time_ns).get(..10).unwrap_or_default().to_string();
            let record = event_record(token, event, name, person, &mut added).map(|mut r| {
                if reported != person {
                    r.insert("email".into(), reported.as_str().into());
                }
                r
            });
            if *said {
                // Text was sent (OTEL_LOG_USER_PROMPTS or OTEL_LOG_TOOL_DETAILS is on). It stops here.
                added.add(&day, person, &token.team, "content_dropped", "", 1.0);
            }
            if let Some(mut record) = record {
                if *said {
                    record.insert("content_dropped".into(), true.into());
                }
                added.records.push(record);
            }
        }

        // Metrics: a point newer than the last of its series counts. A delta point adds its value; a cumulative
        // one adds what the total grew by since the last.
        let mut by_session: BTreeMap<(String, String), [Map<String, Value>; 2]> = BTreeMap::new();
        for point in &points {
            let Some((metric, label)) = metric_of(point) else {
                continue;
            };
            let reported = token.reported(&point.attrs);
            let person = named(&reported);
            let attrs = serde_json::to_string(&point.attrs).unwrap_or_default();
            // A cumulative series starts again with its process, so its start is part of what it is.
            let start = if point.cumulative { point.start_ns } else { 0 };
            let key =
                sha256_hex(format!("{reported}\0{}\0{start}\0{attrs}", point.metric).as_bytes());
            let time = i64::try_from(point.time_ns).unwrap_or(i64::MAX);
            let before: Option<f64> = if point.cumulative {
                tx.query_opt(
                    "SELECT value FROM enterprise_watch_series WHERE key = $1",
                    &[&key],
                )
                .await
                .map_err(failed)?
                .and_then(|r| r.try_get(0).ok())
            } else {
                None
            };
            let newer = tx
                .execute(
                    "INSERT INTO enterprise_watch_series (key, time_ns, value) VALUES ($1, $2, $3) \
                     ON CONFLICT (key) DO UPDATE SET time_ns = excluded.time_ns, value = excluded.value, at = now() \
                     WHERE enterprise_watch_series.time_ns < excluded.time_ns",
                    &[&key, &time, &point.value],
                )
                .await
                .map_err(failed)?;
            let value = (point.value - before.unwrap_or(0.0)).max(0.0);
            if newer == 0 || value == 0.0 || !value.is_finite() {
                continue;
            }
            let day = at(point.time_ns).get(..10).unwrap_or_default().to_string();
            added.add(&day, &person, &token.team, metric, &label, value);
            let session = text(&point.attrs, "session.id", 80).unwrap_or_default();
            let [_, totals] = by_session
                .entry((person.clone(), session))
                .or_insert_with(|| {
                    let mut r = record(token, "metrics", &person, &point.attrs, point.time_ns);
                    if reported != person {
                        r.insert("email".into(), reported.as_str().into());
                    }
                    [r, Map::new()]
                });
            let name = if label.is_empty() {
                metric.to_string()
            } else {
                format!("{metric}:{label}")
            };
            let sum = totals.get(&name).and_then(Value::as_f64).unwrap_or(0.0) + value;
            totals.insert(name, sum.into());
        }
        for (_, [mut record, totals]) in by_session {
            record.insert("totals".into(), totals.into());
            added.records.push(record);
        }

        for ((day, person, team, metric, label), value) in &added.daily {
            tx.execute(
                // ponytail: a row is one person's day, so someone watched through two organizations' tokens on one day is
                // counted under the later one. Put org in the primary key if that happens.
                "INSERT INTO enterprise_watch_daily (day, person, team, metric, label, value, org) VALUES (CAST($1 AS text)::date, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (day, person, metric, label) DO UPDATE SET value = enterprise_watch_daily.value + excluded.value, team = excluded.team, org = excluded.org",
                &[day, person, team, metric, label, value, &token.org],
            )
            .await
            .map_err(failed)?;
        }

        // The records go on file before the sums are kept: a watched unit that is counted is in the chain.
        let (done, mut written) = tokio::sync::mpsc::unbounded_channel();
        for record in &added.records {
            let done = done.clone();
            self.log.append_record_then(record, move |result| {
                let _ = done.send(result);
            });
        }
        drop(done);
        for _ in &added.records {
            match written.recv().await {
                Some(Ok(())) => {}
                Some(Err(err)) => {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        "audit_unavailable",
                        format!(
                            "The audit log could not take the watch records ({err}), so the export was not kept. Claude Code sends it again; fix the audit log on the gateway."
                        ),
                    ));
                }
                None => break,
            }
        }
        tx.commit().await.map_err(failed)?;
        drop(client);
        self.prune().await;
        Ok(())
    }

    /// Once an hour: deletes daily sums past the retention period (the audit export's setting when the install has
    /// one), and what told repeats apart a week ago. Nothing under legal hold.
    async fn prune(&self) {
        {
            let mut pruned = self
                .pruned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pruned.is_some_and(|at| at.elapsed() < PRUNE_EVERY) {
                return;
            }
            *pruned = Some(Instant::now());
        }
        let done = async {
            let client = self.db.client().await?;
            // The retention feature's setting, when the install has its table. An error reading it deletes nothing:
            // legal hold may be on.
            let has: bool = client
                .query_one(
                    "SELECT to_regclass('enterprise_export_settings') IS NOT NULL",
                    &[],
                )
                .await
                .and_then(|r| r.try_get(0))
                .map_err(db_error)?;
            let (days, hold) = if has {
                match client
                    .query_opt(
                        "SELECT retention_days, legal_hold FROM enterprise_export_settings",
                        &[],
                    )
                    .await
                    .map_err(db_error)?
                {
                    Some(row) => (
                        row.try_get(0).map_err(db_error)?,
                        row.try_get(1).map_err(db_error)?,
                    ),
                    None => (KEEP_DAYS, false),
                }
            } else {
                (KEEP_DAYS, false)
            };
            if hold {
                return Ok(());
            }
            client
                .execute(
                    "DELETE FROM enterprise_watch_daily WHERE day < current_date - $1::int",
                    &[&days],
                )
                .await
                .map_err(db_error)?;
            for table in ["enterprise_watch_seen", "enterprise_watch_series"] {
                client
                    .execute(
                        &format!(
                            "DELETE FROM {table} WHERE at < now() - make_interval(days => $1)"
                        ),
                        &[&REPEAT_DAYS],
                    )
                    .await
                    .map_err(db_error)?;
            }
            Ok::<(), String>(())
        };
        if let Err(err) = done.await {
            eprintln!("gantry: watch retention: {err}");
        }
    }
}

// ---------------------------------------------------------------- the receiver

enum Signal {
    Metrics,
    Logs,
}

async fn metrics(Ext(w): Ext<Watch>, headers: HeaderMap, body: Bytes) -> Response {
    receive(w, headers, body, Signal::Metrics).await
}

async fn logs(Ext(w): Ext<Watch>, headers: HeaderMap, body: Bytes) -> Response {
    receive(w, headers, body, Signal::Logs).await
}

const TOO_LARGE: &str = "Send at most 4 MB per export, counted uncompressed. Lower OTEL_METRIC_EXPORT_INTERVAL and OTEL_LOGS_EXPORT_INTERVAL so each export is smaller.";

/// A gzip body unpacked, reading no more than one byte past the limit: a small body that unpacks to gigabytes is
/// refused as any export too large, not held in memory.
fn gunzip(body: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(body)
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut out)?;
    Ok(out)
}

async fn receive(w: Watch, headers: HeaderMap, body: Bytes, signal: Signal) -> Response {
    let token = match w.token(&headers).await {
        Ok(token) => token,
        Err(refused) => return refuse(refused),
    };
    let header = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    };
    let kind = header(header::CONTENT_TYPE);
    let json = kind.contains("json");
    if !json && !kind.contains("protobuf") {
        return fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_protocol",
            "Gantry receives OTLP over HTTP as protobuf or JSON. OTLP over gRPC is not supported. Set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf in Claude Code's managed settings.",
        );
    }
    if body.len() > MAX_BODY {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "too_large", TOO_LARGE);
    }
    let body = match header(header::CONTENT_ENCODING)
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "identity" => body,
        "gzip" => match gunzip(&body) {
            Ok(plain) if plain.len() > MAX_BODY => {
                return fail(StatusCode::PAYLOAD_TOO_LARGE, "too_large", TOO_LARGE);
            }
            Ok(plain) => plain.into(),
            Err(err) => {
                return fail(
                    StatusCode::BAD_REQUEST,
                    "invalid_export",
                    &format!(
                        "The export says Content-Encoding: gzip and is not readable as gzip ({err}). Send it as Claude Code does with OTEL_EXPORTER_OTLP_COMPRESSION=gzip, or leave that setting out."
                    ),
                );
            }
        },
        _ => {
            return fail(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_encoding",
                "Gantry receives OTLP exports uncompressed or as gzip. Set OTEL_EXPORTER_OTLP_COMPRESSION=gzip in Claude Code's settings, or remove it.",
            );
        }
    };
    let read = match (&signal, json) {
        (Signal::Metrics, true) => otlp::metrics_json(&body).map(|p| (p, Vec::new())),
        (Signal::Metrics, false) => otlp::metrics_proto(&body).map(|p| (p, Vec::new())),
        (Signal::Logs, true) => otlp::logs_json(&body).map(|e| (Vec::new(), e)),
        (Signal::Logs, false) => otlp::logs_proto(&body).map(|e| (Vec::new(), e)),
    };
    let (points, events) = match read {
        Ok(read) => read,
        Err(err) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "invalid_export",
                &format!(
                    "The export could not be read: {err}. Send it as Claude Code does, with OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf or http/json."
                ),
            );
        }
    };
    if let Err(refused) = w.keep(&token, points, events).await {
        return refuse(refused);
    }
    // An empty Export*ServiceResponse, in the encoding the export came in.
    if json {
        Json(json!({ "partialSuccess": {} })).into_response()
    } else {
        (
            [(header::CONTENT_TYPE, "application/x-protobuf")],
            Bytes::new(),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------- the admin API

impl Watch {
    /// The tokens `admin` may see: every one, or those within their role's organization and teams.
    async fn tokens(&self, admin: &Admin) -> Result<Vec<Value>, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                &format!(
                    "SELECT id, label, person, team, created_by, to_char(created_at AT TIME ZONE 'UTC', {TIME}), to_char(expires_at AT TIME ZONE 'UTC', {TIME}), \
                     coalesce(to_char(last_used AT TIME ZONE 'UTC', {TIME}), ''), \
                     CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at < now() THEN 'expired' \
                     WHEN last_used IS NULL THEN 'waiting for the first export' ELSE 'receiving' END \
                     , org FROM enterprise_watch_tokens ORDER BY created_at"
                ),
                &[],
            )
            .await
            .map_err(db_error)?;
        Ok(rows
            .iter()
            .map(|r| {
                let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
                json!({ "id": get(0), "label": get(1), "person": get(2), "team": get(3), "org": get(9), "created_by": get(4),
                        "created_at": get(5), "expires_at": get(6), "last_export": get(7), "status": get(8) })
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

    /// Creates a token, recorded first. `Ok` is (id, token, expires_at).
    async fn create(
        &self,
        console: &Console,
        admin: &Admin,
        body: &Value,
    ) -> Result<(String, String, String), Refusal> {
        let action = "watch_token_created";
        let field = |name: &str| body[name].as_str().unwrap_or("").trim().to_string();
        let (label, team, person) = (field("label"), field("team"), field("person"));
        let orgs = self.policy.with(|p| p.orgs().to_vec()).unwrap_or_default();
        let (org, other) = match token_org(admin, &field("org"), &orgs) {
            Ok(org) => (org, None),
            Err(refusal) => (String::new(), Some(refusal)),
        };
        let days = body["days"]
            .as_i64()
            .map_or(DEFAULT_DAYS, |n| i32::try_from(n).unwrap_or(i32::MAX));
        let problem = if role_of(admin) == Role::Viewer {
            Some((
                StatusCode::FORBIDDEN,
                "read_only",
                "Your role is viewer. An owner or admin can create watch tokens.".to_string(),
            ))
        } else if label.is_empty() || label.chars().count() > 64 {
            Some((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Send a label of 1 to 64 characters, such as claude-team-engineering.".to_string(),
            ))
        } else if !team.is_empty() && !config::valid_name(&team) {
            Some((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!(
                    "{team:?} is not a team name: use letters, digits, dot, dash or underscore, or leave it out."
                ),
            ))
        } else if person.chars().count() > 200 || person.contains(char::is_whitespace) {
            Some((StatusCode::BAD_REQUEST, "invalid_request", "A person is a name or an email address of at most 200 characters without spaces, as their Gantry key names them.".to_string()))
        } else if let Some(refusal) = other {
            Some(refusal)
        } else if let Some(message) = outside(admin, &org, &team, "watch token") {
            Some((StatusCode::FORBIDDEN, "outside_role", message))
        } else if !(1..=MAX_DAYS).contains(&days) {
            Some((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("A token lasts 1 to {MAX_DAYS} days; {days} is outside that."),
            ))
        } else {
            None
        };
        if let Some(refusal) = problem {
            let _ = console
                .audit(
                    Some(admin),
                    action,
                    json!({ "label": label }),
                    Some(refusal.1),
                )
                .await;
            return Err(refusal);
        }
        let token = format!("{PREFIX}{}", random_hex(32).map_err(unavailable)?);
        let id = format!("wt-{}", random_hex(4).map_err(unavailable)?);
        console
            .audit(
                Some(admin),
                action,
                json!({ "id": id, "label": label, "team": team, "person": person, "org": org, "days": days }),
                None,
            )
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let client = self.db.client().await.map_err(unavailable)?;
        let row = client
            .query_one(
                &format!(
                    "INSERT INTO enterprise_watch_tokens (id, label, person, team, token_sha256, created_by, expires_at, org) \
                     VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7), $8) RETURNING to_char(expires_at AT TIME ZONE 'UTC', {TIME})"
                ),
                &[&id, &label, &person, &team, &sha256_hex(token.as_bytes()), &admin.name, &days, &org],
            )
            .await
            .map_err(|e| unavailable(db_error(e)))?;
        Ok((id, token, row.try_get(0).unwrap_or_default()))
    }

    /// Revokes a token, recorded first. `Ok(false)` when there is no token by that ID that still works.
    async fn revoke(&self, console: &Console, admin: &Admin, id: &str) -> Result<bool, Refusal> {
        let action = "watch_token_revoked";
        if role_of(admin) == Role::Viewer {
            let _ = console
                .audit(Some(admin), action, json!({ "id": id }), Some("read_only"))
                .await;
            return Err((
                StatusCode::FORBIDDEN,
                "read_only",
                "Your role is viewer. An owner or admin can revoke watch tokens.".into(),
            ));
        }
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
            .audit(Some(admin), action, json!({ "id": id }), None)
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let client = self.db.client().await.map_err(unavailable)?;
        let changed = client
            .execute(
                "UPDATE enterprise_watch_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
                &[&id],
            )
            .await
            .map_err(|e| unavailable(db_error(e)))?;
        Ok(changed > 0)
    }

    /// What was watched in the last `days` days within `admin`'s reach (the install, or their role's organization
    /// and teams): sums in all, per person, per model and per tool, and where the five steps stand for watched people.
    async fn summary(&self, admin: &Admin, days: i32) -> Result<Value, String> {
        let client = self.db.client().await?;
        let known = self.people(&client).await?;
        let rows = client
            .query(
                "SELECT person, team, metric, label, sum(value)::float8, to_char(max(day), 'YYYY-MM-DD'), org FROM enterprise_watch_daily \
                 WHERE day > current_date - $1::int GROUP BY person, team, org, metric, label ORDER BY person, metric, label",
                &[&days],
            )
            .await
            .map_err(db_error)?;
        type Sums = BTreeMap<String, f64>;
        let mut totals = Sums::new();
        let mut people: BTreeMap<String, (String, String, Sums)> = BTreeMap::new();
        let (mut models, mut tools): (BTreeMap<String, Sums>, BTreeMap<String, Sums>) =
            Default::default();
        for r in &rows {
            let get = |i| r.try_get::<_, String>(i).unwrap_or_default();
            let (person, team, metric, label) = (get(0), get(1), get(2), get(3));
            if !admin.covers(&get(6), &team, None) {
                continue;
            }
            let value: f64 = r.try_get(4).unwrap_or(0.0);
            *totals.entry(metric.clone()).or_default() += value;
            let entry = people.entry(person).or_default();
            entry.0 = entry.0.clone().max(team);
            entry.1 = entry.1.clone().max(get(5));
            *entry.2.entry(metric.clone()).or_default() += value;
            if !label.is_empty() {
                let by = if metric.starts_with("tool") || metric.starts_with("edits") {
                    &mut tools
                } else {
                    &mut models
                };
                *by.entry(label).or_default().entry(metric).or_default() += value;
            }
        }
        let list = |name: &str, map: BTreeMap<String, Sums>| -> Vec<Value> {
            map.into_iter()
                .map(|(k, sums)| json!({ name: k, "metrics": sums }))
                .collect()
        };
        let seen = if people.is_empty() {
            "waiting for the first export"
        } else {
            "on"
        };
        // Someone no key, team or member list has: their email stays their name, and they are listed.
        let strangers: Vec<&String> = people
            .keys()
            .filter(|person| !known.name(person).1)
            .collect();
        Ok(json!({
            "days": days,
            "totals": totals,
            "not_known_members": strangers,
            "not_known_members_note": "Not a known member: no key, team or member has this email, so this person's watched use joins no gateway traffic. Give their key `metadata: { email: ... }`, or add them to a team or to Members.",
            "people": people.iter().map(|(person, (team, last, sums))| json!({ "person": person, "team": team, "known": !strangers.contains(&person), "last_day": last, "metrics": sums })).collect::<Vec<_>>(),
            "models": list("model", models),
            "tools": list("tool", tools),
            "note": "Costs are Claude Code's own estimates at list price. Seat usage within a Claude plan is not billed per dollar.",
            "steps": {
                "see": { "status": seen, "from": "Claude Code's telemetry: who, which models, tokens, estimated cost, tools" },
                "know": { "status": seen, "from": "the request log, analytics, /admin/usage, coverage and alerts, source watch" },
                "limit": { "status": NEEDS_TRAFFIC },
                "protect": { "status": NEEDS_TRAFFIC },
                "prove": { "status": seen, "from": "watch records in the audit chain, exported and retained as every record" },
            },
        }))
    }
}

async fn list_tokens(
    State(console): State<Console>,
    Ext(w): Ext<Watch>,
    headers: HeaderMap,
) -> Response {
    let Some(admin) = api_admin(&console, &w.keys, &headers).await else {
        return not_admin();
    };
    match w.tokens(&admin).await {
        Ok(tokens) => Json(json!({ "tokens": tokens })).into_response(),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

async fn create_token(
    State(console): State<Console>,
    Ext(w): Ext<Watch>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // A browser's cookie alone must not create tokens from another site.
    if bearer(&headers).is_empty() && !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = api_admin(&console, &w.keys, &headers).await else {
        return not_admin();
    };
    let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    match w.create(&console, &admin, &body).await {
        Ok((id, token, expires)) => (
            StatusCode::CREATED,
            Json(json!({ "id": id, "token": token, "expires_at": expires, "note": "Gantry keeps only the token's hash and cannot show it again." })),
        )
            .into_response(),
        Err(refused) => refuse(refused),
    }
}

async fn revoke_token(
    State(console): State<Console>,
    Ext(w): Ext<Watch>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Response {
    if bearer(&headers).is_empty() && !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = api_admin(&console, &w.keys, &headers).await else {
        return not_admin();
    };
    match w.revoke(&console, &admin, &id).await {
        Ok(true) => Json(json!({ "id": id, "status": "revoked" })).into_response(),
        Ok(false) => fail(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!(
                "No watch token {id} that still works. List them with GET /console/watch/tokens."
            ),
        ),
        Err(refused) => refuse(refused),
    }
}

async fn summary(
    State(console): State<Console>,
    Ext(w): Ext<Watch>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = api_admin(&console, &w.keys, &headers).await else {
        return not_admin();
    };
    let days = uri
        .query()
        .into_iter()
        .flat_map(|q| q.split('&'))
        .find_map(|pair| pair.strip_prefix("days="))
        .and_then(|d| d.parse::<i32>().ok())
        .unwrap_or(30)
        .clamp(1, MAX_DAYS);
    match w.summary(&admin, days).await {
        Ok(summary) => Json(summary).into_response(),
        Err(e) => fail(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", &e),
    }
}

// ---------------------------------------------------------------- gantry watch setup

/// The `env` block that points Claude Code's telemetry at this gateway, as Anthropic's monitoring page names the
/// variables. Protobuf over HTTP is said outright: before Claude Code 2.1.323 the default was gRPC.
pub fn settings(gateway: &str, token: &str) -> Value {
    json!({
        "env": {
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_METRICS_EXPORTER": "otlp",
            "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_ENDPOINT": format!("{gateway}/otlp"),
            "OTEL_EXPORTER_OTLP_HEADERS": format!("Authorization=Bearer {token}"),
        }
    })
}

pub const SETUP_USAGE: &str = "usage: gantry watch setup --gateway <url> (--team <team> | --person <name>) [--org <org>] [--label <text>] [--days <n>] [--token <watch token>]
      Print the Claude Code managed settings that send its telemetry to the gateway's watch receiver (license feature
      watch), for a team on Claude Team or Enterprise seats or for one developer. Creates a watch token through the
      gateway's admin API with the admin key in GANTRY_ADMIN_KEY (90 days unless --days, 1 to 365), or uses --token.";

/// `gantry watch setup`: what it prints.
pub fn setup(args: &[String]) -> Result<String, String> {
    setup_with(args, std::env::var("GANTRY_ADMIN_KEY").ok())
}

/// `setup`, with the admin key the environment gave.
fn setup_with(args: &[String], admin_key: Option<String>) -> Result<String, String> {
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    if args.first().map(String::as_str) != Some("setup") {
        return Err(SETUP_USAGE.into());
    }
    let gateway = flag("--gateway")
        .map(|g| g.trim_end_matches('/').to_string())
        .filter(|g| (g.starts_with("https://") || g.starts_with("http://")) && !g.contains(['?', '#', ' ']))
        .ok_or_else(|| format!("`watch setup` needs --gateway <url>, the address Claude Code reaches the gateway at, such as https://gantry.example.com.\n{SETUP_USAGE}"))?;
    let (team, person) = (flag("--team"), flag("--person"));
    let who = match (&team, &person) {
        (Some(team), None) => format!("team {team}"),
        (None, Some(person)) => person.clone(),
        _ => {
            return Err(format!(
                "`watch setup` needs --team <team> for a team's rollout or --person <name> for one developer, not both.\n{SETUP_USAGE}"
            ));
        }
    };
    let token = match flag("--token") {
        Some(token) if token.starts_with(PREFIX) => token,
        Some(_) => {
            return Err(format!(
                "--token is a watch token, which starts with {PREFIX}. Leave it out to create one."
            ));
        }
        None => {
            let key = admin_key.filter(|k| !k.trim().is_empty()).ok_or(
                "no admin key: set GANTRY_ADMIN_KEY to an admin key of the gateway so a watch token can be created, or pass one you have with --token.",
            )?;
            let mut body = json!({ "label": flag("--label").unwrap_or_else(|| format!("watch-{}", team.as_deref().or(person.as_deref()).unwrap_or_default())), "team": team, "person": person, "org": flag("--org") });
            if let Some(days) = flag("--days") {
                body["days"] = days
                    .parse::<i64>()
                    .map_err(|_| "--days is a whole number of days, 1 to 365.")?
                    .into();
            }
            let url = format!("{gateway}/console/watch/tokens");
            let answer = ureq::post(&url)
                .set("authorization", &format!("Bearer {}", key.trim()))
                .set("content-type", "application/json")
                .send_string(&body.to_string());
            let created: Value = match answer {
                Ok(response) => response
                    .into_json()
                    .map_err(|e| format!("{url} answered something that is not JSON ({e})."))?,
                Err(ureq::Error::Status(status, response)) => {
                    let said: Value = response.into_json().unwrap_or(Value::Null);
                    return Err(format!(
                        "{url} answered {status}: {}",
                        said["error"]["message"].as_str().unwrap_or("no message. Check that --gateway is the gateway's address and GANTRY_ADMIN_KEY one of its admin keys.")
                    ));
                }
                Err(err) => {
                    return Err(format!(
                        "{url} could not be reached ({err}). Check --gateway, or pass a token you have with --token."
                    ));
                }
            };
            created["token"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{url} answered without a token."))?
        }
    };
    let block = settings(&gateway, &token);
    let pretty = serde_json::to_string_pretty(&block).map_err(|e| e.to_string())?;
    let exports: String = block["env"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| format!("export {name}=\"{}\"\n", value.as_str().unwrap_or_default()))
        .collect();
    Ok(format!(
        "Watch setup for {who}. The token is in the settings below and is not shown again: Gantry keeps only its hash.

Managed settings (Claude Team and Enterprise: claude.ai, Organization settings, Claude Code, Managed settings;
or with your device management tool, as the file
  macOS    /Library/Application Support/ClaudeCode/managed-settings.json
  Linux    /etc/claude-code/managed-settings.json
  Windows  C:\\Program Files\\ClaudeCode\\managed-settings.json):

{pretty}

One developer, in the shell that starts Claude Code:

{exports}
Claude Code sends from its next start, about once a minute while it runs. Check with:
  curl -H \"Authorization: Bearer $GANTRY_ADMIN_KEY\" {gateway}/console/watch/summary.json
Watch mode sees and records. Limits and guardrails need API traffic through Gantry."
    ))
}
