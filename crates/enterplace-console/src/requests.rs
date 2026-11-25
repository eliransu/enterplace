//! Requests in the console app (`/console/app/#/requests`): every request through the gateway, newest first,
//! filtered by any dimension, its outcome, cost and latency; the record sheet of one request (`?record=<decision>`)
//! with whether its decision record still proves; and the kept body, which only its rule's viewers may read.
//!
//! Rows come from the store's index when the gateway has one (every replica), else from the local chain. Reading a
//! kept body is recorded in the audit chain first, allowed or refused: a view that cannot be recorded does not happen.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use enterplace_core::{
    config,
    insights::{self, DIMENSIONS, FIELDS, LINKS, Outcome, Query, Row},
    policy::Permission,
};
use serde_json::{Value, json};

use crate::{
    Admin, Console, Form,
    api::{Fail, answer, body_of, ok, sentence, signed_in, text},
    figures::{EST_HEADER, EST_TIP, money, money_est, time_full, time_list},
    html::enc,
    insights::{count, ms, scoped},
    redirect,
};

const PER_PAGE: usize = 50;

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links (Analytics, Start here, the docs) land on the same view.
        .route("/requests", get(|uri: Uri| async move { moved(&uri) }))
        .route("/api/requests", get(list))
        .route("/api/requests/body", post(body))
        .route("/api/requests/{id}", get(record_of))
}

/// The app's Requests route for an old address, keeping its filters, its page and the request it opened.
fn moved(uri: &Uri) -> Response {
    let query = Form::of(uri);
    let known =
        |k: &str| insights::dimensions().any(|d| d.name == k) || FIELDS.contains(&k) || k == "page";
    let mut kept: Vec<String> = Vec::new();
    for (name, value) in query.pairs() {
        // The old sheet opened with `open=`; the app's record sheet is `record=`, as the Audit log's is.
        let name = if name == "open" { "record" } else { name };
        if !value.is_empty() && (known(name) || name == "record") {
            kept.push(format!("{name}={}", enc(value)));
        }
    }
    let mut to = "/console/app/#/requests".to_string();
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

fn not_for(admin: &Admin, permission: Permission) -> Fail {
    Fail(
        StatusCode::FORBIDDEN,
        format!(
            "Your role, {}, does not have the {} permission this page needs. Ask an Enterplace admin to add it to the role under roles: in the policy.",
            admin.role,
            permission.word()
        ),
    )
}

/// The outcome in the Audit log's words ("Allowed", "Refused: unknown key") and the tag kind that colors it.
fn outcome(row: &Row) -> Value {
    let (kind, text) = match row.outcome() {
        // Observe mode or a shadow period let it through: the row says what would have stopped it.
        Outcome::Allowed => match would_refuse(&row.line) {
            Some(code) if code == "guardrail_blocked" => ("warn", "Would block".to_string()),
            Some(code) => (
                "warn",
                format!("Would refuse: {}", crate::pages::code_words(&code)),
            ),
            // A guardrail under warn or mask let it through: the row names what it found, as the Audit log does.
            None => match acted(&row.line) {
                Some((action, kind)) if action == "mask" => ("warn", format!("Masked: {kind}")),
                Some((_, kind)) => ("warn", format!("Found: {kind}")),
                None => ("allow", "Allowed".to_string()),
            },
        },
        Outcome::Refused if row.code == "guardrail_blocked" => ("block", "Blocked".to_string()),
        Outcome::Refused => (
            "refused",
            format!("Refused: {}", crate::pages::code_words(&row.code)),
        ),
        Outcome::Error => (
            "warn",
            match (row.code.as_str(), row.status) {
                ("", Some(status)) => format!("Error {status}"),
                ("", None) => "Error".to_string(),
                (code, _) => format!("Error {code}"),
            },
        ),
    };
    json!({ "kind": kind, "text": text })
}

/// The code of the first refusal observe mode or a shadow period let through, read from the decision record.
fn would_refuse(line: &str) -> Option<String> {
    if !line.contains("\"would_refuse\"") {
        return None;
    }
    let record: Value = serde_json::from_str(line).ok()?;
    let first = record.get("would_refuse")?.as_array()?.first()?;
    Some(
        first
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

/// The first finding a guardrail masked, else the first it warned of, as (action, kind), read from the decision record.
fn acted(line: &str) -> Option<(String, String)> {
    if !line.contains("\"guardrails\"") {
        return None;
    }
    let record: Value = serde_json::from_str(line).ok()?;
    let findings = record.get("guardrails")?.as_array()?;
    ["mask", "warn"].into_iter().find_map(|action| {
        findings
            .iter()
            .find(|f| f.get("action").and_then(Value::as_str) == Some(action))
            .map(|f| {
                let kind = f.get("kind").and_then(Value::as_str).unwrap_or("guardrail");
                (action.to_string(), kind.to_string())
            })
    })
}

/// Proof shows only where it fails: a row that checks out needs no tag saying so.
fn proof(row: &Row) -> Value {
    match (row.checks_out(), row.linked) {
        (true, true) => Value::Null,
        (true, false) => json!({ "kind": "warn", "text": "Unlinked" }),
        (false, _) => json!({ "kind": "block", "text": "Changed" }),
    }
}

/// A request's cost as a table shows it. A subscription request's is marked as an estimate: its seat is what is paid.
fn cost(row: &Row) -> String {
    match row.cost_usd {
        None => "-".into(),
        Some(cost) if row.estimate => money_est(cost),
        Some(cost) => money(cost),
    }
}

fn tokens(row: &Row) -> String {
    match (row.input_tokens, row.output_tokens) {
        (None, None) => "-".to_string(),
        (i, o) => count(i.unwrap_or(0) + o.unwrap_or(0)),
    }
}

/// The filter fields as the page lays them out: five up front, the rest folded behind More filters, which opens by
/// itself while one of its own is set, so a set filter is never hidden.
fn filters(query: &Query) -> Value {
    let label = |name: &str| {
        query
            .labels
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
            .to_string()
    };
    // A date picker only holds a day: a link that carries a full time keeps it in a text field instead.
    let day = |v: &str| if v.len() > 10 { "text" } else { "date" };
    let field = |name: &str, label: &str, value: String, kind: &str, more: bool| json!({ "name": name, "label": label, "value": value, "kind": kind, "more": more });
    let up_front = ["person", "team", "model"];
    let mut out: Vec<Value> = up_front
        .iter()
        .filter_map(|name| DIMENSIONS.iter().find(|d| d.name == *name))
        .map(|d| field(d.name, d.label, label(d.name), "text", false))
        .collect();
    out.push(field(
        "from",
        "From",
        query.from.clone(),
        day(&query.from),
        false,
    ));
    out.push(field("to", "To", query.to.clone(), day(&query.to), false));
    // The session an events guardrail gave a request is filtered by like a dimension; its turn is read in the row.
    for d in DIMENSIONS
        .iter()
        .filter(|d| !up_front.contains(&d.name))
        .chain(LINKS.iter().filter(|d| d.name == "session"))
    {
        out.push(field(d.name, d.label, label(d.name), "text", true));
    }
    let number = |v: Option<f64>| v.map(|v| v.to_string()).unwrap_or_default();
    let whole = |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_default();
    for (name, label, value) in [
        ("code", "Refusal code", query.code.clone()),
        ("finding", "Guardrail finding", query.finding.clone()),
        ("min_cost", "Cost at least, USD", number(query.min_cost)),
        ("max_cost", "Cost at most, USD", number(query.max_cost)),
        ("min_ms", "Latency at least, ms", whole(query.min_ms)),
        ("max_ms", "Latency at most, ms", whole(query.max_ms)),
    ] {
        out.push(field(name, label, value, "text", true));
    }
    Value::Array(out)
}

async fn list(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            if !admin.may(Permission::SeeRecords) {
                return Err(not_for(&admin, Permission::SeeRecords));
            }
            let form = Form::of(&uri);
            let mut query = Query::parse(&|name| form.get(name).to_string())
                .map_err(|problem| crate::api::bad(sentence(&problem)))?;
            // What the person asked for, before their role's reach is added: the reach is not theirs to clear.
            let asked = query.pairs();
            let up_front = ["outcome", "id", "from", "to", "person", "team", "model"];
            let more_open = asked.iter().any(|(k, _)| !up_front.contains(&k.as_str()));
            let fields = filters(&query);
            scoped(&admin, &mut query);
            let page_no: usize = form.get("page").parse().unwrap_or(1).max(1);
            query.offset = (page_no - 1) * PER_PAGE;
            // One more than a page says whether there is an older page.
            query.limit = PER_PAGE + 1;
            let found = crate::insights::rows(&console, &query).await.map_err(|problem| {
                Fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "{} Check that this gateway can reach its store or its audit log file, then reload the page.",
                        sentence(&problem)
                    ),
                )
            })?;
            let more = found.len() > PER_PAGE;
            let shown = &found[..found.len().min(PER_PAGE)];
            let rows: Vec<Value> = shown
                .iter()
                .map(|row| {
                    json!({
                        "id": row.id,
                        "time": time_list(&row.time),
                        "person": row.label("person"),
                        "team": row.label("team"),
                        "model": row.label("model"),
                        "provider": row.label("provider"),
                        "outcome": outcome(row),
                        "proof": proof(row),
                        "tokens": tokens(row),
                        "cost": cost(row),
                        "estimate": row.estimate,
                        "latency": ms(row.latency_ms),
                    })
                })
                .collect();
            let empty = if !shown.is_empty() {
                Value::Null
            } else if asked.is_empty() && page_no == 1 {
                // Nothing at all yet: what fills the page, as Start here words it for every page.
                let base = crate::base();
                crate::start::empty_for("Requests", &base).map_or(Value::Null, |e| {
                    json!({
                        "title": e.title,
                        "body": e.body,
                        // Without the right to issue keys, only the docs link is offered.
                        "action": admin.may(Permission::IssueKeys).then(|| json!({ "label": e.action.0, "href": e.action.1 })),
                        "docs": format!("{}{}", crate::start::DOCS, e.docs),
                        "command": format!("export ANTHROPIC_BASE_URL={base}"),
                        // The Code tab of the Claude desktop app sets ANTHROPIC_BASE_URL itself, so nothing ever arrives from it.
                        "notes": [
                            "Claude Code on a Claude subscription needs this one line and no key. Other tools take a key: Coding agents shows their lines.",
                            "Using the Claude desktop app? Its Code tab ignores your base URL. Run claude in a terminal.",
                        ],
                    })
                })
            } else {
                json!({
                    "title": "No request matches",
                    "body": "No request in the log matches these filters.",
                    "action": { "label": "Show every request", "href": "#/requests" },
                })
            };
            Ok(ok(json!({
                "lead": "Every request, newest first. New ones appear as they arrive.",
                "filters": fields,
                "more_open": more_open,
                "rows": rows,
                "est_header": format!("USD ({EST_HEADER})"),
                "est_tip": EST_TIP,
                "empty": empty,
                "pager": {
                    "text": format!("Page {page_no}, {} requests", shown.len()),
                    "page": page_no,
                    "newer": page_no > 1,
                    "older": more,
                },
            })))
        }
        .await,
    )
}

/// The request in words, for the sheet's title: who, which model, and what Enterplace did.
fn row_title(row: &Row) -> String {
    let or = |v: &str, none: &str| {
        if v.is_empty() {
            none.to_string()
        } else {
            v.to_string()
        }
    };
    let outcome = match row.outcome() {
        Outcome::Allowed => "allowed".to_string(),
        Outcome::Refused if row.code == "guardrail_blocked" => "blocked".to_string(),
        Outcome::Refused if !row.code.is_empty() => format!("refused ({})", row.code),
        Outcome::Refused => "refused".to_string(),
        Outcome::Error => "error".to_string(),
    };
    format!(
        "{}, {}, {outcome}",
        or(row.label("person"), "unknown person"),
        or(row.label("model"), "no model")
    )
}

/// One request's record sheet: six facts up front, then its details and its proof, each folded until opened.
async fn record_of(
    State(console): State<Console>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            if !admin.may(Permission::SeeRecords) {
                return Err(not_for(&admin, Permission::SeeRecords));
            }
            let mut one = Query {
                id: id.trim().to_string(),
                limit: 1,
                ..Query::default()
            };
            // A person kept to some teams opens only their requests, as the list shows only theirs.
            scoped(&admin, &mut one);
            let row = crate::insights::rows(&console, &one)
                .await
                .map_err(|problem| Fail(StatusCode::SERVICE_UNAVAILABLE, format!("{} Check that this gateway can reach its store or its audit log file, then reload the page.", sentence(&problem))))?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Fail(
                        StatusCode::NOT_FOUND,
                        format!(
                            "No request has the ID {id}, or it is outside what your role may see. Open the request from the list, or check the ID in the Audit log."
                        ),
                    )
                })?;
            Ok(ok(sheet(&row)))
        }
        .await,
    )
}

fn sheet(row: &Row) -> Value {
    let or_dash = |v: &str| {
        if v.is_empty() {
            "-".to_string()
        } else {
            v.to_string()
        }
    };
    let tokens = match (row.input_tokens, row.output_tokens) {
        (None, None) => "-".to_string(),
        (i, o) => format!(
            "{} ({} in, {} out)",
            count(i.unwrap_or(0) + o.unwrap_or(0)),
            i.map_or("-".into(), count),
            o.map_or("-".into(), count)
        ),
    };
    let facts = json!([
        ["Time", time_full(&row.time)],
        ["Person", or_dash(row.label("person"))],
        ["Model", or_dash(row.label("model"))],
        ["Tokens", tokens],
        [if row.estimate { "Cost, est." } else { "Cost" }, cost(row)],
        ["Rule", or_dash(&row.rule)],
    ]);
    // Everything else the records hold, minus what the six facts and the title already say.
    let mut details: Vec<(&str, String)> = DIMENSIONS
        .iter()
        .chain(LINKS)
        .filter(|d| d.name != "person" && d.name != "model")
        .filter_map(|d| row.labels.get(d.name).map(|v| (d.label, v.join(", "))))
        .collect();
    let said = outcome(row);
    details.push((
        "Outcome",
        said["text"].as_str().unwrap_or_default().to_string(),
    ));
    details.push(("Latency", ms(row.latency_ms)));
    details.push(("Route", row.path.clone()));
    if !row.findings.is_empty() {
        details.push(("Findings", row.findings.join(", ")));
    }
    if let Some(status) = row.status {
        details.push(("Provider status", status.to_string()));
    }
    details.push(("Charged", money(row.charged_usd)));
    if !row.stages.is_empty() {
        // Where the time went inside Enterplace, in the order the request passed each stage.
        let stages: Vec<String> = row
            .stages
            .iter()
            .map(|(name, took)| format!("{} {took:.2} ms", name.replace('_', " ")))
            .collect();
        details.push(("Time by stage", stages.join(", ")));
    }
    let explained = match (row.checks_out(), row.linked) {
        (true, true) => {
            "The decision record hashes to the hash the chain holds for it, and follows the record before it."
        }
        (true, false) => {
            "The decision record hashes to its hash, and its prev does not match the record read before it. Run enterplace audit verify on that gateway."
        }
        (false, _) => {
            "The decision record does not hash to the hash it carries: it was changed after it was written. Run enterplace audit verify on that gateway."
        }
    };
    let chain = format!(
        "{} record {}",
        if row.replica.is_empty() {
            "this gateway,"
        } else {
            row.replica.as_str()
        },
        row.n
    );
    json!({
        "id": row.id,
        "title": row_title(row),
        // A proof that fails is the one thing worth seeing before opening anything.
        "failed": proof(row),
        "facts": facts,
        "details": details,
        "proof": {
            "facts": [["Decision", row.id], ["Chain", chain], ["Hash", row.hash]],
            "text": explained,
            "audit": format!("/console/audit?record={}", enc(&row.id)),
        },
        "body": row.body,
    })
}

/// Reads a kept body for one of its rule's viewers. The view is recorded in the audit chain first, allowed or
/// refused; a view that cannot be recorded does not happen.
async fn body(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            // A view is recorded, so it is a change: one from another site is refused before anything is read.
            let admin = signed_in(&console, &headers, true).await?;
            if !admin.may(Permission::SeeBodies) {
                return Err(not_for(&admin, Permission::SeeBodies));
            }
            let id = text(&body_of(&bytes)?, "id").to_string();
            let bodies = insights::attached(&console.config().audit).bodies;
            let found = match (&bodies, insights::id_ok(&id)) {
                (Some(bodies), true) => bodies.body(&id).await,
                _ => Ok(None),
            };
            let body = match found {
                Ok(Some(body)) => body,
                Ok(None) => {
                    let _ = console
                        .audit(Some(&admin), "view_body", json!({ "id": id }), Some("no_body"))
                        .await;
                    return Err(Fail(
                        StatusCode::NOT_FOUND,
                        "Enterplace keeps no body for this decision: its rule does not capture, the body expired, or no master key is set on this gateway. Set capture: on the rule to keep the next ones.".into(),
                    ));
                }
                Err(problem) => {
                    return Err(Fail(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!(
                            "The body did not open: {problem} Check the store and the master key of this gateway, then try again."
                        ),
                    ));
                }
            };
            // The rule's viewers when the body was kept, and its viewers now if the rule is still in the policy:
            // removing someone from a rule takes back what it kept before.
            let now = config::load(&console.config().policy, Some(&console.config().keys))
                .ok()
                .and_then(|l| {
                    l.policy
                        .rule_list()
                        .iter()
                        .find(|r| r.name == body.rule)
                        .map(|r| {
                            r.limits
                                .capture
                                .as_ref()
                                .map(|c| c.viewers.clone())
                                .unwrap_or_default()
                        })
                });
            let may = insights::may_view(&body.viewers, &admin.name, &admin.team, &admin.role)
                && now.is_none_or(|v| {
                    insights::may_view(&v, &admin.name, &admin.team, &admin.role)
                });
            let target = json!({ "id": id, "rule": body.rule });
            if !may {
                let _ = console
                    .audit(Some(&admin), "view_body", target, Some("not_a_viewer"))
                    .await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Rule \"{}\" lets only its viewers read what it keeps ({}). This refusal is recorded. Ask an admin to add you to capture: viewers in the policy.",
                        body.rule,
                        body.viewers.join(", ")
                    ),
                ));
            }
            if let Err(problem) = console.audit(Some(&admin), "view_body", target, None).await {
                return Err(Fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Not recorded, so not shown: {problem}"),
                ));
            }
            // JSON is shown indented, so a long body reads line by line; an event stream as it came.
            let pretty = |text: &str| {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
                    .unwrap_or_else(|| text.to_string())
            };
            Ok(ok(json!({
                "id": id,
                "lead": "Redacted by Enterplace's secrets and PII detectors before it was kept. This view is recorded in the audit log.",
                "facts": [
                    ["Rule", body.rule],
                    ["Kept", body.time],
                    ["Deleted after", enterplace_core::audit::rfc3339(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(body.expires)
                    )],
                    ["Viewers", body.viewers.join(", ")],
                ],
                "request": pretty(&body.request),
                "answer": pretty(&body.answer),
            })))
        }
        .await,
    )
}
