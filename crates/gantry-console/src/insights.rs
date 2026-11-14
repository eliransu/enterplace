//! The Requests and Analytics pages, and the kept body view. No Claude Design screen exists for them: they are
//! built from the console's existing components (panel, toolbar, tabs, table, sheet, stats, chart, meter, facts,
//! code) and tokens only, laid out as the Audit log and Spend screens are.
//!
//! Rows come from the store's index when the gateway has one (every replica), else from the local chain. Each row
//! shows whether its decision record still hashes to what the chain holds.

use std::fmt::Write as _;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use gantry_core::{
    config,
    insights::{self, DIMENSIONS, Outcome, Pace, Query, Row, Stats},
    policy::{Period, Who},
};
use serde_json::json;

use gantry_core::policy::Permission;

use crate::{
    Admin, Console, Form,
    html::{button, empty, enc, esc, facts, head, icon, link, motif, pager, tag, thousands},
    not_permitted, page, pages, redirect, same_origin,
};

const PER_PAGE: usize = 50;

/// Keeps a person whose role is kept to one organization to that organization's requests.
fn scoped(admin: &Admin, query: &mut Query) {
    if let Some(org) = &admin.org {
        query.labels.push(("org".into(), org.clone()));
    }
}

fn money(usd: f64) -> String {
    if usd > 0.0 && usd < 0.01 {
        return format!("{usd:.4}");
    }
    let cents = (usd * 100.0).round() as u64;
    format!(
        "{}.{:02}",
        thousands(usize::try_from(cents / 100).unwrap_or(usize::MAX)),
        cents % 100
    )
}

fn ms(v: Option<u64>) -> String {
    match v {
        None => "-".into(),
        Some(v) if v >= 10_000 => format!("{:.1} s", v as f64 / 1000.0),
        Some(v) => format!("{} ms", thousands(usize::try_from(v).unwrap_or(usize::MAX))),
    }
}

fn count(v: u64) -> String {
    thousands(usize::try_from(v).unwrap_or(usize::MAX))
}

/// The rows a query asks for: from the index of every gateway on the store, or from the local chain.
async fn rows(console: &Console, query: &Query) -> Result<Vec<Row>, String> {
    let audit = console.config().audit.clone();
    if let Some(index) = insights::attached(&audit).index {
        return index.rows(query).await;
    }
    let query = query.clone();
    // ponytail: the whole chain is folded on every page, as the audit page reads it. The store's index answers
    // when logs grow large.
    tokio::task::spawn_blocking(move || insights::fold_chain(&audit).map(|all| query.select(&all)))
        .await
        .map_err(|err| format!("the request log stopped before it finished: {err}."))?
}

fn source(console: &Console) -> &'static str {
    if insights::attached(&console.config().audit).index.is_some() {
        "every gateway on the store"
    } else {
        "this gateway's audit log"
    }
}

fn href(base: &str, pairs: &[(String, String)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect();
    if query.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", query.join("&"))
    }
}

fn with(query: &Query, name: &str, value: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = query
        .pairs()
        .into_iter()
        .filter(|(k, _)| k != name)
        .collect();
    pairs.push((name.to_string(), value.to_string()));
    pairs
}

fn outcome_tag(row: &Row) -> String {
    match row.outcome() {
        Outcome::Allowed => tag("allow", "Allow", ""),
        Outcome::Refused if row.code == "guardrail_blocked" => tag("block", "Block", &row.code),
        Outcome::Refused => tag("refused", "Refused", &row.code),
        Outcome::Error => tag(
            "warn",
            "Error",
            &if row.code.is_empty() {
                row.status.map(|s| s.to_string()).unwrap_or_default()
            } else {
                row.code.clone()
            },
        ),
    }
}

fn proof_tag(row: &Row) -> String {
    match (row.checks_out(), row.linked) {
        (true, true) => tag("allow", "Verified", ""),
        (true, false) => tag("warn", "Unlinked", ""),
        (false, _) => tag("block", "Changed", ""),
    }
}

fn error_page(
    console: &Console,
    admin: &crate::Admin,
    uri: &Uri,
    title: &str,
    current: &str,
    problem: &str,
) -> Response {
    let main = format!(
        "{}\n{}",
        head(title, "", ""),
        empty(
            &motif(&["", "flame"], &["empty"], (2, 1), true, true),
            "This did not load",
            &esc(problem),
            &link("Show everything", "quiet", uri.path(), false),
        )
    );
    console.page(StatusCode::OK, admin, current, uri, &main)
}

pub(crate) async fn requests_page(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    if !admin.may(Permission::SeeRecords) {
        return not_permitted(&admin, Permission::SeeRecords);
    }
    let form = Form::of(&uri);
    let mut query = match Query::parse(&|name| form.get(name).to_string()) {
        Ok(query) => query,
        Err(problem) => {
            return error_page(&console, &admin, &uri, "Requests", "Requests", &problem);
        }
    };
    scoped(&admin, &mut query);
    let page_no: usize = form.get("page").parse().unwrap_or(1).max(1);
    query.offset = (page_no - 1) * PER_PAGE;
    // One more than a page says whether there is an older page.
    query.limit = PER_PAGE + 1;
    let found = match rows(&console, &query).await {
        Ok(found) => found,
        Err(problem) => {
            return error_page(&console, &admin, &uri, "Requests", "Requests", &problem);
        }
    };
    let more = found.len() > PER_PAGE;
    let shown = &found[..found.len().min(PER_PAGE)];

    let tabs: String = [("", "All"), ("allowed", "Allowed"), ("refused", "Refused"), ("error", "Errors")]
        .iter()
        .map(|(value, label)| {
            format!(
                r#"<button class="g-tab t-body" type="submit" name="outcome" value="{value}" aria-pressed="{}">{label}</button>"#,
                query.outcome == *value
            )
        })
        .collect();
    let hidden: String = query
        .pairs()
        .iter()
        .filter(|(k, _)| k != "outcome" && k != "id")
        .map(|(k, v)| {
            format!(
                r#"<input type="hidden" name="{}" value="{}">"#,
                esc(k),
                esc(v)
            )
        })
        .collect();
    let toolbar = format!(
        r#"<form class="g-toolbar" method="get" action="/console/requests">
<div class="g-search">{}<input class="g-input t-body" type="search" name="id" value="{}" aria-label="Decision ID" placeholder="Decision ID"></div>
<div class="g-tabs" role="group" aria-label="Show">{tabs}</div>{hidden}
</form>"#,
        icon("search"),
        esc(&query.id)
    );
    let field = |name: &str, label: &str, value: &str, kind: &str| {
        format!(
            r#"<input class="g-input t-body" style="flex: 1 1 calc(var(--space-24) * 2); width: auto; min-width: 0" type="{kind}" name="{name}" value="{}" aria-label="{label}" placeholder="{label}">"#,
            esc(value)
        )
    };
    let mut filters = String::new();
    for d in DIMENSIONS {
        let value = query
            .labels
            .iter()
            .find(|(k, _)| k == d.name)
            .map_or("", |(_, v)| v.as_str());
        filters.push_str(&field(d.name, d.label, value, "text"));
    }
    let number = |v: Option<f64>| v.map(|v| v.to_string()).unwrap_or_default();
    let whole = |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_default();
    for (name, label, value, kind) in [
        ("code", "Refusal code", query.code.clone(), "text"),
        (
            "finding",
            "Guardrail finding",
            query.finding.clone(),
            "text",
        ),
        ("from", "From (UTC date)", query.from.clone(), "text"),
        ("to", "To (UTC date)", query.to.clone(), "text"),
        (
            "min_cost",
            "Cost at least, USD",
            number(query.min_cost),
            "text",
        ),
        (
            "max_cost",
            "Cost at most, USD",
            number(query.max_cost),
            "text",
        ),
        (
            "min_ms",
            "Latency at least, ms",
            whole(query.min_ms),
            "text",
        ),
        ("max_ms", "Latency at most, ms", whole(query.max_ms), "text"),
    ] {
        filters.push_str(&field(name, label, &value, kind));
    }
    // Folded away until asked for, and open while any of them is set, so the list stays first on a phone.
    let set = query
        .pairs()
        .iter()
        .any(|(k, _)| k != "outcome" && k != "id");
    let filter_form = format!(
        r#"<details{}><summary class="t-body">Filters: person, team, key, model, provider, tag, agent, code, finding, time, cost, latency</summary><form class="g-toolbar" method="get" action="/console/requests"><input type="hidden" name="outcome" value="{}">{filters}{}{}</form></details>"#,
        if set { " open" } else { "" },
        esc(&query.outcome),
        button("Filter", "quiet", "submit", ""),
        link("Clear", "quiet", "/console/requests", false)
    );

    let mut body = String::new();
    for row in shown {
        let cell = |dimension: &str| {
            let value = row.label(dimension);
            if value.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<a href="{}">{}</a>"#,
                    esc(&href("/console/requests", &with(&query, dimension, value))),
                    esc(value)
                )
            }
        };
        let open = href("/console/requests", &with(&query, "open", &row.id));
        let open = if page_no > 1 {
            format!("{open}&page={page_no}")
        } else {
            open
        };
        let _ = writeln!(
            body,
            r#"<tr><td>{}<span class="g-table__sub">{}</span></td><td>{}<span class="g-table__sub">{}</span></td><td>{}</td><td class="g-table__wide">{}<span class="g-table__sub">{}</span></td><td class="g-table__num">{}</td><td class="g-table__num">{}</td><td class="g-table__wide">{}<span class="g-table__sub"><a href="{}">Open</a></span></td></tr>"#,
            esc(row
                .time
                .get(..19)
                .unwrap_or(&row.time)
                .replace('T', " ")
                .as_str()),
            esc(&row.id),
            cell("person"),
            cell("team"),
            outcome_tag(row),
            cell("model"),
            cell("provider"),
            row.cost_usd.map_or("-".into(), money),
            ms(row.latency_ms),
            proof_tag(row),
            esc(&open),
        );
    }
    let list = if shown.is_empty() {
        empty(
            &motif(&["", "", ""], &["empty"], (3, 1), false, true),
            "No request matches",
            "No request in the log matches these filters.",
            &link("Show every request", "quiet", "/console/requests", false),
        )
    } else {
        let page_href = |p: usize| {
            esc(&format!(
                "{}{}page={p}",
                href("/console/requests", &query.pairs()),
                if query.pairs().is_empty() { "?" } else { "&" }
            ))
        };
        format!(
            "<div class=\"g-table-wrap\"><table class=\"g-table g-table--stack t-mono-sm\">\n<thead class=\"t-tag\"><tr><th>Time (UTC) and decision</th><th>Person and team</th><th>Outcome</th><th>Model and provider</th><th class=\"g-table__num\">USD</th><th class=\"g-table__num\">Latency</th><th>Proof</th></tr></thead>\n<tbody>\n{body}</tbody>\n</table></div>\n{}",
            pager(
                &format!("Page {page_no}, {} requests", shown.len()),
                (
                    "Newer requests",
                    (page_no > 1).then(|| page_href(page_no - 1))
                ),
                ("Older requests", more.then(|| page_href(page_no + 1))),
            )
        )
    };

    let open = form.get("open");
    let sheet = if open.is_empty() {
        String::new()
    } else {
        let one = Query {
            id: open.to_string(),
            limit: 1,
            ..Query::default()
        };
        let close = href("/console/requests", &query.pairs());
        match rows(&console, &one)
            .await
            .ok()
            .and_then(|r| r.into_iter().next())
        {
            Some(row) => row_sheet(&row, &close),
            None => format!(
                r#"<div class="g-scrim g-scrim--sheet"><aside class="g-sheet" role="dialog" aria-modal="true" aria-labelledby="row-title"><div class="g-pager"><span></span><a class="g-btn g-btn--quiet g-btn--icon" href="{}" aria-label="Close" data-close>{}</a></div><h2 class="t-md" id="row-title" style="margin: 0">No request has this ID</h2></aside></div>"#,
                esc(&close),
                icon("close")
            ),
        }
    };
    let main = format!(
        "{}\n<div class=\"g-panel g-stack\">\n{toolbar}\n{filter_form}\n{list}\n</div>",
        head(
            "Requests",
            &format!(
                "Every request's decision, usage and latency, from {}, newest first. Each row's proof recomputes its decision record's hash. Prompt and answer text are never here.",
                source(&console)
            ),
            &link("Analytics", "quiet", "/console/analytics", false)
        )
    );
    page(
        StatusCode::OK,
        pages::tool_page(
            "Requests",
            &admin.label(),
            "/console/requests",
            &form,
            &main,
            &sheet,
        ),
    )
}

fn row_sheet(row: &Row, close: &str) -> String {
    let labels: Vec<(&str, String)> = DIMENSIONS
        .iter()
        .filter_map(|d| {
            row.labels
                .get(d.name)
                .map(|v| (d.label, esc(&v.join(", "))))
        })
        .collect();
    let proof = match (row.checks_out(), row.linked) {
        (true, true) => {
            "The decision record hashes to the hash the chain holds for it, and follows the record before it."
        }
        (true, false) => {
            "The decision record hashes to its hash, and its prev does not match the record read before it. Run gantry audit verify on that gateway."
        }
        (false, _) => {
            "The decision record does not hash to the hash it carries: it was changed after it was written. Run gantry audit verify on that gateway."
        }
    };
    let mut pairs: Vec<(&str, String)> = vec![
        ("Decision", esc(&row.id)),
        ("Time", esc(&row.time)),
        ("Outcome", outcome_tag(row)),
        ("Rule", esc(&row.rule)),
        ("Route", esc(&row.path)),
    ];
    pairs.extend(labels);
    pairs.extend([
        ("Findings", esc(&row.findings.join(", "))),
        (
            "Provider status",
            row.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
        ),
        (
            "Tokens in, out",
            format!(
                "{}, {}",
                row.input_tokens.map_or("-".into(), count),
                row.output_tokens.map_or("-".into(), count)
            ),
        ),
        ("Cost, USD", row.cost_usd.map_or("-".into(), money)),
        ("Charged, USD", money(row.charged_usd)),
        ("Latency", ms(row.latency_ms)),
        (
            "Chain",
            esc(&format!(
                "{} record {}",
                if row.replica.is_empty() {
                    "this gateway,"
                } else {
                    row.replica.as_str()
                },
                row.n
            )),
        ),
        ("Hash", esc(&row.hash)),
    ]);
    let body = if row.body {
        format!(
            r#"<form method="post" action="/console/requests/body"><input type="hidden" name="id" value="{}">{}</form><p class="t-small g-muted" style="margin: 0">Its rule keeps the redacted request and answer. Reading them is recorded in the audit log, and only the rule's viewers may.</p>"#,
            esc(&row.id),
            button("Read the kept body", "", "submit", "")
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="g-scrim g-scrim--sheet">
<aside class="g-sheet" role="dialog" aria-modal="true" aria-labelledby="row-title">
<div class="g-pager"><span></span><a class="g-btn g-btn--quiet g-btn--icon" href="{}" aria-label="Close" data-close>{}</a></div>
<div class="g-stack">
<h2 class="t-md" id="row-title" style="margin: 0">Request {}</h2>
{}
<p class="t-small" style="margin: 0">{}</p>
<p class="t-small g-muted" style="margin: 0">{proof}</p>
{}
{body}
</div>
</aside>
</div>"#,
        esc(close),
        icon("close"),
        esc(&row.id),
        proof_tag(row),
        facts(&pairs),
        link(
            "Open its audit record",
            "quiet",
            &format!("/console/audit?record={}", enc(&row.id)),
            true
        ),
    )
}

/// Reads a kept body for one of its rule's viewers. The view is recorded in the audit chain first, allowed or
/// refused; a view that cannot be recorded does not happen.
pub(crate) async fn body_view(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    text: String,
) -> Response {
    if !same_origin(&headers) {
        return crate::foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    if !admin.may(Permission::SeeBodies) {
        return not_permitted(&admin, Permission::SeeBodies);
    }
    let id = Form::parse(&text).get("id").trim().to_string();
    let shown = |title: &str, problem: &str| {
        let main = format!(
            "{}\n{}",
            head(title, "", ""),
            empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                title,
                &esc(problem),
                &link(
                    "Back to the requests",
                    "quiet",
                    &format!("/console/requests?open={}", enc(&id)),
                    false
                ),
            )
        );
        console.page(StatusCode::FORBIDDEN, &admin, "Requests", &uri, &main)
    };
    let bodies = insights::attached(&console.config().audit).bodies;
    let found = match (&bodies, insights::id_ok(&id)) {
        (Some(bodies), true) => bodies.body(&id).await,
        _ => Ok(None),
    };
    let body = match found {
        Ok(Some(body)) => body,
        Ok(None) => {
            let _ = console
                .audit(
                    Some(&admin),
                    "view_body",
                    json!({ "id": id }),
                    Some("no_body"),
                )
                .await;
            return shown(
                "No kept body",
                "Gantry keeps no body for this decision: its rule does not capture, the body expired, or no master key is set on this gateway.",
            );
        }
        Err(problem) => return shown("The body did not open", &problem),
    };
    // The rule's viewers when the body was kept, and its viewers now if the rule is still in the policy: removing
    // someone from a rule takes back what it kept before.
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
        && now.is_none_or(|v| insights::may_view(&v, &admin.name, &admin.team, &admin.role));
    let target = json!({ "id": id, "rule": body.rule });
    if !may {
        let _ = console
            .audit(Some(&admin), "view_body", target, Some("not_a_viewer"))
            .await;
        return shown(
            "Not one of its viewers",
            &format!(
                "Rule \"{}\" lets only its viewers read what it keeps ({}). This refusal is recorded. Ask an admin to add you to capture: viewers in the policy.",
                body.rule,
                body.viewers.join(", ")
            ),
        );
    }
    if let Err(problem) = console.audit(Some(&admin), "view_body", target, None).await {
        return shown("Not recorded, so not shown", problem);
    }
    let block = |text: &str| {
        // JSON is shown indented, so a long body reads line by line; an event stream as it came.
        let text = serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| text.to_string());
        let lines: Vec<(usize, String, &str)> = text
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, esc(l), ""))
            .collect();
        crate::html::code(&lines)
    };
    let main = format!(
        "{}\n<div class=\"g-panel g-stack\">{}</div>\n<div class=\"g-panel g-stack\"><h2 class=\"t-md\" style=\"margin: 0\">Request, as sent</h2>{}</div>\n<div class=\"g-panel g-stack\"><h2 class=\"t-md\" style=\"margin: 0\">Answer</h2>{}</div>",
        head(
            &format!("Body of {}", esc(&id)),
            "Redacted by Gantry's secrets and PII detectors before it was kept. This view is recorded in the audit log.",
            &link(
                "Back to the request",
                "quiet",
                &format!("/console/requests?open={}", enc(&id)),
                false
            )
        ),
        facts(&[
            ("Rule", esc(&body.rule)),
            ("Kept", esc(&body.time)),
            (
                "Deleted after",
                esc(&gantry_core::audit::rfc3339(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(body.expires)
                ))
            ),
            ("Viewers", esc(&body.viewers.join(", "))),
        ]),
        block(&body.request),
        block(&body.answer)
    );
    console.page(StatusCode::OK, &admin, "Requests", &uri, &main)
}

/// Bars for a series, with its scale, as the Spend chart draws them.
fn chart(label: &str, points: &[(String, f64)], show: impl Fn(f64) -> String) -> String {
    let top = points.iter().map(|p| p.1).fold(0.0, f64::max);
    let top = if top > 0.0 { top } else { 1.0 };
    let bars: String = points
        .iter()
        .map(|(at, v)| {
            format!(
                r#"<div class="g-bar" style="--g-bar-value: {:.1}%" title="{}: {}"></div>"#,
                v / top * 100.0,
                esc(at),
                esc(&show(*v))
            )
        })
        .collect();
    let every = points.len().div_ceil(6).max(1);
    let marks: String = points
        .iter()
        .enumerate()
        .map(|(i, (at, _))| {
            if i % every == 0 {
                format!(
                    "<span>{}</span>",
                    esc(&match at.get(11..13) {
                        Some(hour) => format!("{hour}:00"),
                        None => at.get(5..).unwrap_or(at).to_string(),
                    })
                )
            } else {
                "<span></span>".into()
            }
        })
        .collect();
    format!(
        r#"<div class="g-chart" role="img" aria-label="{}"><div class="g-chart__scale t-mono-sm"><span>{}</span><span>{}</span><span>0</span></div><div class="g-chart__plot"><span class="g-chart__grid" style="--g-at: 50%"></span><span class="g-chart__grid" style="--g-at: 100%"></span>{bars}</div><div class="g-chart__days t-mono-sm">{marks}</div></div>"#,
        esc(label),
        esc(&show(top)),
        esc(&show(top / 2.0))
    )
}

fn stat(figure: &str, label: &str) -> String {
    format!(
        r#"<div class="g-stat"><p class="g-stat__figure t-numeral">{figure}</p><p class="g-stat__label t-body">{label}</p></div>"#
    )
}

pub(crate) async fn analytics_page(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    if !admin.may(Permission::SeeSpend) {
        return not_permitted(&admin, Permission::SeeSpend);
    }
    let form = Form::of(&uri);
    let mut query = match Query::parse(&|name| form.get(name).to_string()) {
        Ok(query) => query,
        Err(problem) => {
            return error_page(&console, &admin, &uri, "Analytics", "Analytics", &problem);
        }
    };
    scoped(&admin, &mut query);
    let window = match form.get("window") {
        "24h" => ("24h", 86_400, true, "the last 24 hours"),
        "30d" => ("30d", 30 * 86_400, false, "the last 30 days"),
        _ => ("7d", 7 * 86_400, false, "the last 7 days"),
    };
    let dimension = DIMENSIONS
        .iter()
        .find(|d| d.name == form.get("by"))
        .copied()
        .unwrap_or(DIMENSIONS[2]);
    let now = insights::now_secs();
    let at = |secs: u64| {
        gantry_core::audit::rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
    };
    if query.from.is_empty() {
        query.from = at(now.saturating_sub(window.1));
    }
    query.limit = insights::MAX_ROWS;
    // With a store the sums come from SQL over every matching request; the local chain folds up to MAX_ROWS.
    let summed = match insights::attached(&console.config().audit).index {
        Some(index) => index.analytics(&query, window.2, dimension.name).await,
        None => rows(&console, &query)
            .await
            .map(|found| insights::analytics(&found, window.2, dimension.name)),
    };
    let summed = match summed {
        Ok(summed) => summed,
        Err(problem) => {
            return error_page(&console, &admin, &uri, "Analytics", "Analytics", &problem);
        }
    };
    let all = summed.totals.clone();
    let pct = |s: &Stats, p: f64| ms(s.percentile(p));
    let stats = format!(
        r#"<div class="g-panel g-stats">{}{}{}{}{}{}{}{}</div>"#,
        stat(&count(all.requests), "requests"),
        stat(&count(all.refused), "refused"),
        stat(&count(all.errors), "errors"),
        stat(
            &count(all.input_tokens + all.output_tokens),
            "tokens in and out"
        ),
        stat(&format!("${}", money(all.cost_usd)), "cost"),
        stat(&pct(&all, 50.0), "latency p50"),
        stat(&pct(&all, 95.0), "latency p95"),
        stat(&pct(&all, 99.0), "latency p99"),
    );
    // Every hour or day of the window, empty ones too, so the bars keep time.
    let had: std::collections::BTreeMap<String, Stats> = summed.series.into_iter().collect();
    let (step, width) = if window.2 { (3600, 13) } else { (86_400, 10) };
    let mut series: Vec<(String, Stats)> = Vec::new();
    let mut t = now.saturating_sub(window.1) + step;
    while t < now + step {
        let key = at(t).get(..width).unwrap_or_default().to_string();
        if series.last().is_none_or(|(k, _)| *k != key) {
            let stats = had.get(&key).cloned().unwrap_or_default();
            series.push((key, stats));
        }
        t += step;
    }
    let per = |f: &dyn Fn(&Stats) -> f64| -> Vec<(String, f64)> {
        series.iter().map(|(k, s)| (k.clone(), f(s))).collect()
    };
    let charts = [
        ("Requests", per(&|s| s.requests as f64), "requests"),
        (
            "Refused and errors",
            per(&|s| (s.refused + s.errors) as f64),
            "requests",
        ),
        ("Cost, USD", per(&|s| s.cost_usd), "usd"),
        (
            "Tokens",
            per(&|s| (s.input_tokens + s.output_tokens) as f64),
            "tokens",
        ),
        (
            "Latency p95",
            per(&|s| s.percentile(95.0).unwrap_or_default() as f64),
            "ms",
        ),
    ];
    let mut panels = String::new();
    for (title, points, unit) in charts {
        let show = move |v: f64| match unit {
            "usd" => format!("${}", money(v)),
            "ms" => ms(Some(v as u64)),
            _ => count(v.round() as u64),
        };
        let _ = write!(
            panels,
            r#"<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">{title}, per {}</h2>{}</div>"#,
            if window.2 { "hour" } else { "day" },
            if all.requests == 0 {
                r#"<p class="t-small g-muted" style="margin: 0">No requests in this window.</p>"#
                    .to_string()
            } else {
                chart(title, &points, show)
            }
        );
    }

    let base: Vec<(String, String)> = query
        .pairs()
        .into_iter()
        .filter(|(k, _)| k != "from")
        .collect();
    let pick = |name: &str, value: &str| {
        let mut pairs: Vec<(String, String)> =
            base.iter().filter(|(k, _)| k != name).cloned().collect();
        pairs.push(("window".into(), window.0.into()));
        pairs.push(("by".into(), dimension.name.into()));
        pairs.retain(|(k, _)| k != name);
        pairs.push((name.into(), value.into()));
        href("/console/analytics", &pairs)
    };
    let windows: String = [("24h", "24 hours"), ("7d", "7 days"), ("30d", "30 days")]
        .iter()
        .map(|(v, l)| {
            format!(
                r#"<a class="g-tab t-body" href="{}" aria-pressed="{}" style="text-decoration: none">{l}</a>"#,
                esc(&pick("window", v)),
                window.0 == *v
            )
        })
        .collect();
    let bys: String = DIMENSIONS
        .iter()
        .map(|d| {
            format!(
                r#"<a class="g-tab t-body" href="{}" aria-pressed="{}" style="text-decoration: none">{}</a>"#,
                esc(&pick("by", d.name)),
                d.name == dimension.name,
                d.label
            )
        })
        .collect();
    let ranked = summed.ranking;
    let ranking_rows: String = ranked
        .iter()
        .take(25)
        .enumerate()
        .map(|(i, (value, s))| {
            let shown = if value.is_empty() { "(none)".to_string() } else { value.clone() };
            format!(
                r#"<tr><td>{}. <a href="{}">{}</a></td><td class="g-table__num">{}</td><td class="g-table__num g-table__wide">{}</td><td class="g-table__num g-table__wide">{}</td><td class="g-table__num g-table__wide">{}</td><td class="g-table__num">{}</td><td class="g-table__num g-table__wide">{}</td><td class="g-table__num g-table__wide">{}</td></tr>"#,
                i + 1,
                esc(&href("/console/requests", &with(&Query::default(), dimension.name, value))),
                esc(&shown),
                count(s.requests),
                count(s.refused),
                count(s.errors),
                count(s.input_tokens + s.output_tokens),
                money(s.cost_usd),
                pct(s, 50.0),
                pct(s, 95.0),
            )
        })
        .collect();
    let ranking = format!(
        r#"<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">By {}, most costly first</h2><div class="g-tabs" role="group" aria-label="Group by">{bys}</div><div class="g-table-wrap"><table class="g-table g-table--stack t-mono-sm"><thead class="t-tag"><tr><th>{}</th><th class="g-table__num">Requests</th><th class="g-table__num">Refused</th><th class="g-table__num">Errors</th><th class="g-table__num">Tokens</th><th class="g-table__num">USD</th><th class="g-table__num">p50</th><th class="g-table__num">p95</th></tr></thead><tbody>{ranking_rows}</tbody></table></div></div>"#,
        dimension.label.to_lowercase(),
        dimension.label
    );
    let forecasts = forecasts(&console, &admin, now).await;
    let filtered = if query.labels.is_empty() && query.outcome.is_empty() {
        String::new()
    } else {
        format!(
            " Filtered to {}.",
            esc(&query
                .pairs()
                .iter()
                .filter(|(k, _)| k != "from" && k != "to")
                .map(|(k, v)| format!("{k} {v}"))
                .collect::<Vec<_>>()
                .join(", "))
        )
    };
    let main = format!(
        "{}\n<div class=\"g-tabs\" role=\"group\" aria-label=\"Window\">{windows}</div>\n{stats}\n<div class=\"g-split\">{panels}</div>\n{ranking}\n{forecasts}",
        head(
            "Analytics",
            &format!(
                "Requests, tokens, cost, latency, refusals and errors over {}, from {}.{filtered}",
                window.3,
                source(&console)
            ),
            &link("Requests", "quiet", "/console/requests", false)
        )
    );
    console.page(StatusCode::OK, &admin, "Analytics", &uri, &main)
}

/// Each budget in the policy, what it spent this period, and when it runs out at the pace it has spent at.
async fn forecasts(console: &Console, admin: &Admin, now: u64) -> String {
    let Ok(loaded) = config::load(&console.config().policy, Some(&console.config().keys)) else {
        return String::new();
    };
    let budgets: Vec<_> = loaded
        .policy
        .rule_list()
        .iter()
        .filter_map(|r| r.limits.budget().map(|b| (r, b)))
        .collect();
    if budgets.is_empty() {
        return format!(
            r#"<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">Budget forecasts</h2>{}</div>"#,
            empty(
                &motif(&["", "", ""], &["empty", "empty"], (3, 1), false, true),
                "No budgets yet",
                "The policy sets no budget, so nothing runs out.",
                &link("Add a budget to the policy", "", "/console/policy", false),
            )
        );
    }
    let (month_start, _) = insights::period(now, false);
    let query = Query {
        from: gantry_core::audit::rfc3339(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(month_start),
        ),
        limit: insights::MAX_ROWS,
        ..Query::default()
    };
    let mut query = query;
    scoped(admin, &mut query);
    let found = rows(console, &query).await.unwrap_or_default();
    let mut out = String::new();
    for (rule, budget) in budgets {
        // ponytail: a forecast window is a UTC day or month; a budget per week, per 6h or in a time zone is
        // forecast over the month. Use Period::label and resets here if those budgets need their own window.
        let per_day = budget.per == Period::Day;
        let (start, end) = insights::period(now, per_day);
        let spent_by = |dimension: &str| {
            let mut by: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
            for r in &found {
                if insights::unix_secs(&r.time).is_some_and(|t| t >= start) {
                    *by.entry(r.label(dimension).to_string()).or_default() += r.charged_usd;
                }
            }
            by
        };
        let (label, spent) = match &rule.who {
            Who::Team(team) => (
                format!("team {team}"),
                spent_by("team")
                    .get(team.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            Who::Name(name) => (
                name.clone(),
                spent_by("person")
                    .get(name.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            // A budget for each person (of every key, or of the keys with a tag): the one heading out first.
            Who::Any | Who::Tag(_) => spent_by("person")
                .into_iter()
                .max_by(|a, b| a.1.total_cmp(&b.1))
                .map_or(("each person".into(), 0.0), |(p, s)| {
                    (format!("{p} (each person)"), s)
                }),
        };
        let note = match insights::pace(spent, budget.usd, start, now, end) {
            Pace::Idle => "Nothing spent yet this period.".to_string(),
            Pace::Spent => "Spent. Refused until the period resets.".to_string(),
            Pace::Lasts => "At this pace it lasts the period.".to_string(),
            Pace::RunsOut(at) => format!(
                "At this pace it runs out at {} UTC.",
                gantry_core::audit::rfc3339(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(at)
                )
                .get(..16)
                .unwrap_or_default()
                .replace('T', " ")
            ),
        };
        let pct = if budget.usd > 0.0 {
            (spent / budget.usd * 100.0).round().min(100.0) as u32
        } else {
            0
        };
        let state = if matches!(
            insights::pace(spent, budget.usd, start, now, end),
            Pace::Spent | Pace::RunsOut(_)
        ) {
            r#" data-state="over""#
        } else {
            ""
        };
        let _ = write!(
            out,
            r#"<div class="g-meter"{state} style="--g-meter-value: {pct}%"><div class="g-meter__row"><span class="t-mono-lg">{}</span><span class="t-mono-sm">${} of ${} a {}</span></div><div class="g-meter__track" role="meter" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100" aria-label="{} budget used"><div class="g-meter__fill"></div></div><span class="t-small g-muted">Rule {}. {note}</span></div>"#,
            esc(&label),
            money(spent),
            money(budget.usd),
            if per_day { "day" } else { "month" },
            esc(&label),
            esc(&rule.name),
        );
    }
    format!(
        r#"<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">Budget forecasts</h2>{out}</div>"#
    )
}
