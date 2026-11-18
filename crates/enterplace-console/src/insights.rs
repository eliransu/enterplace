//! The Requests page and the kept body view. No Claude Design screen exists for them: they are built from the
//! console's existing components (panel, toolbar, tabs, table, sheet, facts, code) and tokens only, laid out as the
//! Audit log screen is. Analytics moved to the console app (`analytics.rs`).
//!
//! Rows come from the store's index when the gateway has one (every replica), else from the local chain. Each row
//! shows whether its decision record still hashes to what the chain holds.

use std::fmt::Write as _;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use enterplace_core::{
    config,
    insights::{self, DIMENSIONS, LINKS, Outcome, Query, Row},
};
use serde_json::json;

use enterplace_core::policy::Permission;

use crate::{
    Admin, Console, Form,
    figures::{EST_HEADER, EST_TIP, money, money_est, time_full, time_list},
    html::{button, empty, enc, esc, facts, head, icon, link, motif, pager, tag, thousands},
    not_permitted, page, pages, redirect, same_origin,
};

const PER_PAGE: usize = 50;

/// Keeps a person whose role is kept to an organization, teams or customers to their requests.
pub(crate) fn scoped(admin: &Admin, query: &mut Query) {
    if let Some(org) = &admin.org {
        query.labels.push(("org".into(), org.clone()));
    }
    if !admin.teams.is_empty() {
        query.within.push(("team".into(), admin.teams.clone()));
    }
    if !admin.customers.is_empty() {
        query
            .within
            .push(("customer".into(), admin.customers.clone()));
    }
}

/// A list on its first page: an empty one there means nothing at all.
fn offset_zero(form: &Form) -> bool {
    matches!(form.get("page"), "" | "1")
}

pub(crate) fn ms(v: Option<u64>) -> String {
    match v {
        None => "-".into(),
        Some(v) if v >= 10_000 => format!("{:.1} s", v as f64 / 1000.0),
        Some(v) => format!("{} ms", thousands(usize::try_from(v).unwrap_or(usize::MAX))),
    }
}

pub(crate) fn count(v: u64) -> String {
    thousands(usize::try_from(v).unwrap_or(usize::MAX))
}

/// The rows a query asks for: from the index of every gateway on the store, or from the local chain.
pub(crate) async fn rows(console: &Console, query: &Query) -> Result<Vec<Row>, String> {
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

pub(crate) fn href(base: &str, pairs: &[(String, String)]) -> String {
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

pub(crate) fn with(query: &Query, name: &str, value: &str) -> Vec<(String, String)> {
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
        // The same words as the Audit log: "Allowed", "Refused: unknown key".
        Outcome::Allowed => tag("allow", "Allowed", ""),
        Outcome::Refused if row.code == "guardrail_blocked" => tag("block", "Blocked", ""),
        Outcome::Refused => tag("refused", "Refused:", &crate::pages::code_words(&row.code)),
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
    // A labeled field, as the design system's Field draws one, sized so five share a row on a desktop and two on a phone.
    let field = |name: &str, label: &str, value: &str, kind: &str| {
        format!(
            r#"<div class="g-field" style="flex: 1 1 calc(var(--space-24) + var(--space-10)); min-width: 0"><label class="g-field__label t-tag g-caps" for="f-{name}">{label}</label><input class="g-input t-body" style="min-width: 0" id="f-{name}" type="{kind}" name="{name}" value="{}"></div>"#,
            esc(value)
        )
    };
    let label = |name: &str| {
        query
            .labels
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    };
    // A date picker only holds a day: a link that carries a full time keeps it in a text field instead.
    let day = |v: &str| if v.len() > 10 { "text" } else { "date" };
    let up_front = ["person", "team", "model"];
    let mut front: String = up_front
        .iter()
        .filter_map(|name| DIMENSIONS.iter().find(|d| d.name == *name))
        .map(|d| field(d.name, d.label, label(d.name), "text"))
        .collect();
    front.push_str(&field("from", "From", &query.from, day(&query.from)));
    front.push_str(&field("to", "To", &query.to, day(&query.to)));
    let mut folded = String::new();
    // The session an events guardrail gave a request is filtered by like a dimension; its turn is read in the row.
    for d in DIMENSIONS
        .iter()
        .filter(|d| !up_front.contains(&d.name))
        .chain(LINKS.iter().filter(|d| d.name == "session"))
    {
        folded.push_str(&field(d.name, d.label, label(d.name), "text"));
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
        folded.push_str(&field(name, label, &value, "text"));
    }
    // Folded until asked for, and open while one of its own filters is set, so a set filter is never hidden.
    let set = query.pairs().iter().any(|(k, _)| {
        !matches!(k.as_str(), "outcome" | "id" | "from" | "to") && !up_front.contains(&k.as_str())
    });
    let filter_form = format!(
        r#"<form class="g-stack" method="get" action="/console/requests"><input type="hidden" name="outcome" value="{}"><div class="g-toolbar" style="align-items: flex-end">{front}{}{}</div><details{} class="g-stack" style="gap: var(--space-3)"><summary class="t-small g-link">More filters</summary><div class="g-toolbar" style="align-items: flex-end">{folded}</div></details></form>"#,
        esc(&query.outcome),
        button("Filter", "quiet", "submit", ""),
        link("Clear", "quiet", "/console/requests", false),
        if set { " open" } else { "" },
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
            r#"<tr><td><a href="{}" aria-label="Open request {}">{}</a></td><td>{}<span class="g-table__sub">{}</span></td><td>{}{}</td><td class="g-table__wide">{}<span class="g-table__sub">{}</span></td><td class="g-table__num">{}</td><td class="g-table__num">{}</td><td class="g-table__num">{}</td></tr>"#,
            esc(&open),
            esc(&row.id),
            esc(&time_list(&row.time)),
            cell("person"),
            cell("team"),
            outcome_tag(row),
            // Proof shows only where it fails: a row that checks out needs no tag saying so.
            if row.checks_out() && row.linked {
                String::new()
            } else {
                format!(" {}", proof_tag(row))
            },
            cell("model"),
            cell("provider"),
            match (row.input_tokens, row.output_tokens) {
                (None, None) => "-".to_string(),
                (i, o) => count(i.unwrap_or(0) + o.unwrap_or(0)),
            },
            cost_text(row),
            ms(row.latency_ms),
        );
    }
    let list = if shown.is_empty() && query.pairs().is_empty() && offset_zero(&form) {
        crate::empty_page("Requests", &crate::base(), admin.may(Permission::IssueKeys))
    } else if shown.is_empty() {
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
        let est_head = format!(
            r#"<th class="g-table__num" title="{}">USD ({EST_HEADER})</th>"#,
            esc(EST_TIP)
        );
        format!(
            "<div class=\"g-table-wrap\"><table class=\"g-table g-table--stack t-mono-sm\">\n<thead class=\"t-tag\"><tr><th>Time (UTC)</th><th>Person</th><th>Outcome</th><th>Model</th><th class=\"g-table__num\">Tokens</th>{est_head}<th class=\"g-table__num\">Latency</th></tr></thead>\n<tbody>\n{body}</tbody>\n</table></div>\n{}",
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
            "Every request, newest first. New ones appear as they arrive.",
            ""
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

/// One closed section of the sheet: what a reader opens only when the six facts do not answer.
fn folded(title: &str, inner: &str) -> String {
    format!(
        r#"<details class="g-stack" style="gap: var(--space-3)"><summary class="t-small g-link">{title}</summary>{inner}</details>"#
    )
}

fn row_sheet(row: &Row, close: &str) -> String {
    let tokens = match (row.input_tokens, row.output_tokens) {
        (None, None) => "-".to_string(),
        (i, o) => format!(
            "{} ({} in, {} out)",
            count(i.unwrap_or(0) + o.unwrap_or(0)),
            i.map_or("-".into(), count),
            o.map_or("-".into(), count)
        ),
    };
    let or_dash = |v: &str| {
        if v.is_empty() {
            "-".to_string()
        } else {
            esc(v)
        }
    };
    let six = facts(&[
        ("Time", esc(&time_full(&row.time))),
        ("Person", or_dash(row.label("person"))),
        ("Model", or_dash(row.label("model"))),
        ("Tokens", tokens),
        (
            if row.estimate { "Cost, est." } else { "Cost" },
            cost_text(row),
        ),
        ("Rule", or_dash(&row.rule)),
    ]);
    // Everything else the records hold, minus what the six facts and the title already say.
    let mut more: Vec<(&str, String)> = DIMENSIONS
        .iter()
        .chain(LINKS)
        .filter(|d| d.name != "person" && d.name != "model")
        .filter_map(|d| {
            row.labels
                .get(d.name)
                .map(|v| (d.label, esc(&v.join(", "))))
        })
        .collect();
    more.push(("Outcome", outcome_tag(row)));
    more.push(("Latency", ms(row.latency_ms)));
    more.push(("Route", esc(&row.path)));
    if !row.findings.is_empty() {
        more.push(("Findings", esc(&row.findings.join(", "))));
    }
    if let Some(status) = row.status {
        more.push(("Provider status", status.to_string()));
    }
    more.push(("Charged", money(row.charged_usd)));
    if !row.stages.is_empty() {
        // Where the time went inside Enterplace, in the order the request passed each stage.
        let stages: Vec<String> = row
            .stages
            .iter()
            .map(|(name, took)| format!("{} {took:.2} ms", name.replace('_', " ")))
            .collect();
        more.push(("Time by stage", esc(&stages.join(", "))));
    }
    let proof = match (row.checks_out(), row.linked) {
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
    let chain = esc(&format!(
        "{} record {}",
        if row.replica.is_empty() {
            "this gateway,"
        } else {
            row.replica.as_str()
        },
        row.n
    ));
    let proof = folded(
        "Proof",
        &format!(
            r#"{}<p class="t-small g-muted" style="margin: 0">{proof}</p>{}"#,
            facts(&[
                ("Decision", esc(&row.id)),
                ("Chain", chain),
                ("Hash", esc(&row.hash)),
            ]),
            link(
                "Open its audit record",
                "quiet",
                &format!("/console/audit?record={}", enc(&row.id)),
                true
            ),
        ),
    );
    // A proof that fails is the one thing worth seeing before opening anything.
    let failed = if row.checks_out() && row.linked {
        String::new()
    } else {
        proof_tag(row)
    };
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
<h2 class="t-md" id="row-title" style="margin: 0">{}</h2>
{failed}
{six}
{body}
{}
{proof}
</div>
</aside>
</div>"#,
        esc(close),
        icon("close"),
        esc(&row_title(row)),
        folded("Details", &facts(&more)),
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
                "Enterplace keeps no body for this decision: its rule does not capture, the body expired, or no master key is set on this gateway.",
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
            "Redacted by Enterplace's secrets and PII detectors before it was kept. This view is recorded in the audit log.",
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
                esc(&enterplace_core::audit::rfc3339(
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

/// A request's cost as a table shows it. A subscription request's is marked as an estimate: its seat is what is paid.
fn cost_text(row: &enterplace_core::insights::Row) -> String {
    match row.cost_usd {
        None => "-".into(),
        Some(cost) if row.estimate => {
            format!(
                r#"<span title="{}">{}</span>"#,
                esc(EST_TIP),
                money_est(cost)
            )
        }
        Some(cost) => money(cost),
    }
}
