//! Analytics in the console app (`/console/app/#/usage`): requests, cost and refusals over a window, one chart
//! with a metric switch, a ranking by any dimension, and each budget's forecast at the pace it has spent at.
//!
//! Rows come from the store's index when the gateway has one (every replica), else from the local chain. Everything a
//! test pins (money, latency, the lead line, the empty state, which breakdowns are offered) is worded here, so the app
//! only lays it out.

use std::collections::{BTreeMap, HashMap};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::get,
};
use enterplace_core::{
    config,
    insights::{self, DIMENSIONS, Pace, Query, Stats},
    policy::{Budget, Permission, Policy, ScopeKind, Who},
};
use serde_json::{Value, json};

use crate::{
    Admin, Console, Form,
    api::{Fail, answer, ok, signed_in},
    figures::{EST_TIP, money, money_est, time_list},
    insights::{count, href, ms, rows, scoped, with},
    redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: an old link lands on the same window, breakdown and filters.
        .route("/analytics", get(|uri: Uri| async move { moved(&uri) }))
        .route("/api/analytics", get(analytics))
}

/// Every parameter of the old page is a parameter of the app route, so the query goes over as it is.
fn moved(uri: &Uri) -> Response {
    match uri.query().filter(|q| !q.is_empty()) {
        Some(query) => redirect(&format!("/console/app/#/usage?{query}")),
        None => redirect("/console/app/#/usage"),
    }
}

/// What a coding agent needs to read the view from the admin API. The admin key is left for the person to set.
fn agent_prompt(base: &str, api: &str, by: &str, then: &str) -> String {
    let split = if then.is_empty() {
        String::new()
    } else {
        format!(
            ", each with a split list: its requests by {}",
            then.to_lowercase()
        )
    };
    format!(
        "Read who spends what on AI models from Enterplace, the gateway every model request goes through, and summarize it.\n\n\
         curl -s -H \"Authorization: Bearer $ENTERPLACE_KEY\" \"{base}/admin/usage?{api}\"\n\n\
         ENTERPLACE_KEY is an admin key (or a key whose role has see_spend). I set it in the shell myself: never ask me for \
         it, print it or write it to a file. If it is not set, stop and tell me.\n\n\
         The answer is JSON: totals, and groups, one per {by}{split}. Each has requests, refused, input_tokens, \
         output_tokens, spend_usd and estimated_usd: the part of spend_usd sent with a person's own subscription login, \
         an estimate at API prices, not a bill. Add &format=csv for the same as CSV. Times are UTC. group_by also takes \
         day, hour, team, person, model, provider, key or agent; then takes one or two of them, such as agent,model.\n\n\
         Docs: https://docs.enterplace.dev/reference/admin-api/#get-adminusage"
    )
}

/// The top of the chart's scale: the highest bar rounded up to a figure whose half reads cleanly too (150 and 75,
/// $0.80 and $0.40), not 124 and 62.
fn nice_top(x: f64) -> f64 {
    if x <= 0.0 || !x.is_finite() {
        return 1.0;
    }
    let power = 10f64.powf(x.log10().floor());
    [1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0]
        .into_iter()
        .map(|m| m * power)
        .find(|top| *top >= x * 0.999_999)
        .unwrap_or(10.0 * power)
}

fn at(secs: u64) -> String {
    enterplace_core::audit::rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// A metric the chart can switch to: its query value, its title, how to read it off an hour or day, and its unit.
type Metric = (&'static str, &'static str, fn(&Stats) -> f64, &'static str);

const METRICS: [Metric; 5] = [
    ("requests", "Requests", |s| s.requests as f64, "requests"),
    (
        "errors",
        "Refused and errors",
        |s| (s.refused + s.errors) as f64,
        "requests",
    ),
    ("cost", "Cost, USD", |s| s.cost_usd, "usd"),
    (
        "tokens",
        "Tokens",
        |s| (s.input_tokens + s.output_tokens) as f64,
        "tokens",
    ),
    (
        "latency",
        "Latency p95",
        |s| s.percentile(95.0).unwrap_or_default() as f64,
        "ms",
    ),
];

async fn analytics(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            if !admin.may(Permission::SeeSpend) {
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Your role, {}, does not have the {} permission this page needs. Ask an Enterplace admin to add it to the role under roles: in the policy.",
                        admin.role,
                        Permission::SeeSpend.word()
                    ),
                ));
            }
            let form = Form::of(&uri);
            // A filter that does not parse says which one and how to write it.
            let mut query = Query::parse(&|name| form.get(name).to_string())
                .map_err(|problem| Fail(StatusCode::BAD_REQUEST, problem))?;
            scoped(&admin, &mut query);
            let now = insights::now_secs();
            // This month so far is counted from midnight UTC on the 1st, as a monthly budget is. Its bars start on
            // the 1st: the series below starts one step after `now - seconds`.
            let first = format!("{}01", at(now).get(..8).unwrap_or_default());
            let month = insights::unix_secs(&first).unwrap_or(now);
            let window = match form.get("window") {
                "24h" => ("24h", 86_400, true, "Over the last 24 hours. Times are UTC."),
                "30d" => ("30d", 30 * 86_400, false, "Over the last 30 days. Days are UTC."),
                "month" => (
                    "month",
                    now.saturating_sub(month) + 86_400,
                    false,
                    "This month so far, from the 1st (UTC).",
                ),
                _ => ("7d", 7 * 86_400, false, "Over the last 7 days. Days are UTC."),
            };
            let dimension = DIMENSIONS
                .iter()
                .find(|d| d.name == form.get("by"))
                .copied()
                .unwrap_or(DIMENSIONS[2]);
            let then = insights::then_of(form.get("then"), dimension.name).map_err(|problem| {
                Fail(StatusCode::BAD_REQUEST, format!("Split by: {problem}"))
            })?;
            // A start date from a link pins the window; else it is the window's own.
            let pinned = !query.from.is_empty();
            if !pinned {
                query.from = if window.0 == "month" {
                    first.clone()
                } else {
                    at(now.saturating_sub(window.1))
                };
            }
            query.limit = insights::MAX_ROWS;
            // With a store the sums come from SQL over every matching request; the local chain folds up to MAX_ROWS.
            // The local rows are kept to tell which breakdowns hold anything; the store's sums do not say, so with a
            // store every breakdown is offered.
            let (summed, found) = match insights::attached(&console.config().audit).index {
                Some(index) => (index.analytics(&query, window.2, dimension.name).await, None),
                None => match rows(&console, &query).await {
                    Ok(found) => (
                        Ok(insights::analytics(&found, window.2, dimension.name)),
                        Some(found),
                    ),
                    Err(problem) => (Err(problem), None),
                },
            };
            let summed = summed.map_err(|problem| {
                Fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("The request log did not load: {problem} Check that the gateway can read its audit log or store, then reload the page."),
                )
            })?;
            let all = summed.totals.clone();
            // A split folds the rows: the store's sums are by one dimension at a time.
            // ponytail: folds at most MAX_ROWS rows of the store; a SQL GROUP BY of several labels if a window holds more.
            let ranked: Vec<insights::Split> = if then.is_empty() {
                summed.ranking.iter().map(|(k, s)| (k.clone(), s.clone(), Vec::new())).collect()
            } else {
                let rows = match (&found, insights::attached(&console.config().audit).index) {
                    (Some(found), _) => found.clone(),
                    (None, Some(index)) => index.rows(&query).await.map_err(|problem| {
                        Fail(StatusCode::SERVICE_UNAVAILABLE, format!("The request log did not load: {problem} Check that the gateway can reach its store, then reload the page."))
                    })?,
                    (None, None) => Vec::new(),
                };
                insights::split(&rows, dimension.name, &then)
            };
            if form.get("format") == "csv" {
                return Ok(Response::builder()
                    .header("content-type", "text/csv; charset=utf-8")
                    .header(
                        "content-disposition",
                        format!("attachment; filename=\"enterplace-usage-by-{}.csv\"", dimension.name),
                    )
                    .header("cache-control", "no-store")
                    .body(axum::body::Body::from(insights::usage_csv(dimension.name, &then, &ranked)))
                    .unwrap_or_default());
            }
            // Nothing at all, not a filter that matches nothing: the page says what fills it.
            if all.requests == 0 && query.pairs().iter().all(|(k, _)| k == "from") {
                let empty = crate::start::empty_for("Analytics", &crate::base()).map(|e| {
                    json!({
                        "title": e.title,
                        "body": e.body,
                        // Without the right to make keys, only the docs link is offered.
                        "action": admin.may(Permission::IssueKeys).then(|| json!({ "label": e.action.0, "href": e.action.1 })),
                        "docs": format!("{}{}", crate::start::DOCS, e.docs),
                    })
                });
                return Ok(ok(json!({ "empty": empty })));
            }

            // One value's trend (`trend=team:payments`, from a ranking row): the chart alone is filtered to it, so the
            // ranking still shows what it is one of.
            let bad_trend = || {
                Fail(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "trend is \"{}\". Write it as a dimension and a value, such as trend=team:payments; the dimension is one of {}.",
                        form.get("trend"),
                        DIMENSIONS.iter().map(|d| d.name).collect::<Vec<_>>().join(", ")
                    ),
                )
            };
            let trend = match form.get("trend") {
                "" => None,
                text => {
                    let (name, value) = text
                        .split_once(':')
                        .filter(|(_, v)| !v.is_empty())
                        .ok_or_else(bad_trend)?;
                    let d = DIMENSIONS
                        .iter()
                        .find(|d| d.name == name)
                        .copied()
                        .ok_or_else(bad_trend)?;
                    Some((d, value.to_string()))
                }
            };
            let series = match &trend {
                None => summed.series,
                Some((d, value)) => {
                    let mut only = query.clone();
                    only.labels.push((d.name.to_string(), value.clone()));
                    match (&found, insights::attached(&console.config().audit).index) {
                        (Some(found), _) => {
                            let rows: Vec<insights::Row> =
                                found.iter().filter(|r| only.matches(r)).cloned().collect();
                            insights::series(&rows, window.2)
                        }
                        (None, Some(index)) => index
                            .analytics(&only, window.2, dimension.name)
                            .await
                            .map_err(|problem| {
                                Fail(StatusCode::SERVICE_UNAVAILABLE, format!("The request log did not load: {problem} Check that the gateway can reach its store, then reload the page."))
                            })?
                            .series,
                        (None, None) => Vec::new(),
                    }
                }
            };
            // Every hour or day of the window, empty ones too, so the bars keep time.
            let had: BTreeMap<String, Stats> = series.into_iter().collect();
            let (step, width) = if window.2 { (3600, 13) } else { (86_400, 10) };
            let mut series: Vec<(String, Stats)> = Vec::new();
            let mut t = now.saturating_sub(window.1) + step;
            // Up to now and no further: a window that starts at midnight (this month) would else draw tomorrow.
            while t <= now {
                let key = at(t).get(..width).unwrap_or_default().to_string();
                if series.last().is_none_or(|(k, _)| *k != key) {
                    let stats = had.get(&key).cloned().unwrap_or_default();
                    series.push((key, stats));
                }
                t += step;
            }
            let metric = METRICS
                .iter()
                .find(|m| m.0 == form.get("metric"))
                .unwrap_or(&METRICS[0]);
            let show = |v: f64| match metric.3 {
                "usd" => money(v),
                "ms" => ms(Some(v as u64)),
                _ => count(v.round() as u64),
            };
            let chart = (all.requests > 0).then(|| {
                let values: Vec<f64> = series.iter().map(|(_, s)| (metric.2)(s)).collect();
                let top = values.iter().copied().fold(0.0, f64::max);
                let top = if top > 0.0 { nice_top(top) } else { 1.0 };
                // About six marks under the bars, so the labels never run into each other.
                let every = series.len().div_ceil(6).max(1);
                let last = series.len().saturating_sub(1);
                let points: Vec<Value> = series
                    .iter()
                    .zip(&values)
                    .enumerate()
                    .map(|(i, ((at, _), v))| {
                        let mark = (i % every == 0).then(|| match at.get(11..13) {
                            Some(hour) => format!("{hour}:00"),
                            None => at.get(5..).unwrap_or(at).to_string(),
                        });
                        json!({
                            "at": at,
                            "shown": show(*v),
                            "percent": (v / top * 1000.0).round() / 10.0,
                            "mark": mark,
                            // The current hour or day: the one bar the eye should land on.
                            "now": i == last,
                        })
                    })
                    .collect();
                json!({ "label": metric.1, "top": show(top), "half": show(top / 2.0), "points": points })
            });

            // Four breakdowns answer most questions; the rest wait under More, and one with nothing in it is not
            // offered.
            let first = ["team", "person", "model", "provider"];
            let has_data = |name: &str| {
                found
                    .as_ref()
                    .is_none_or(|f| f.iter().any(|r| !r.label(name).is_empty()))
            };
            let tab = |d: &insights::Dimension| json!({ "name": d.name, "label": d.label });
            let up_front: Vec<Value> = first
                .iter()
                .filter_map(|name| DIMENSIONS.iter().find(|d| d.name == *name))
                .map(tab)
                .collect();
            let more: Vec<Value> = DIMENSIONS
                .iter()
                .filter(|d| !first.contains(&d.name))
                .filter(|d| d.name == dimension.name || has_data(d.name))
                .map(tab)
                .collect();
            let pct = |s: &Stats, p: f64| ms(s.percentile(p));
            let estimated = |s: &Stats| (s.estimated_usd > 0.0).then(|| money_est(s.estimated_usd));
            // A request that named nobody is a problem to fix, never a person, team or key called "unknown".
            let named_by = ["person", "team", "key"].contains(&dimension.name);
            let ranking: Vec<Value> = ranked
                .iter()
                .take(25)
                .map(|(value, s, parts)| {
                    json!({
                        "value": if value.is_empty() { "(none)" } else { value.as_str() },
                        "unnamed": named_by && (value.is_empty() || value == "unknown"),
                        "href": href("/console/requests", &with(&Query::default(), dimension.name, value)),
                        "requests": count(s.requests),
                        "refused": count(s.refused),
                        "errors": count(s.errors),
                        "tokens": count(s.input_tokens + s.output_tokens),
                        "usd": money(s.cost_usd),
                        "estimated": estimated(s),
                        "p50": pct(s, 50.0),
                        "p95": pct(s, 95.0),
                        "parts": parts.iter().map(|(values, s)| json!({
                            "values": values,
                            "requests": count(s.requests),
                            "tokens": count(s.input_tokens + s.output_tokens),
                            "usd": money(s.cost_usd),
                            "estimated": estimated(s),
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            let filtered = if query.labels.is_empty() && query.outcome.is_empty() {
                String::new()
            } else {
                format!(
                    " Filtered to {}.",
                    query
                        .pairs()
                        .iter()
                        .filter(|(k, _)| k != "from" && k != "to")
                        .map(|(k, v)| format!("{k} {v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            // The view as a link that opens it again, and the same numbers for an agent from the admin API.
            let mut view: Vec<(String, String)> = vec![
                ("by".into(), dimension.name.into()),
                ("then".into(), then.join(",")),
                ("window".into(), window.0.into()),
            ];
            if metric.0 != METRICS[0].0 {
                view.push(("metric".into(), metric.0.into()));
            }
            if let Some((d, v)) = &trend {
                view.push(("trend".into(), format!("{}:{v}", d.name)));
            }
            view.extend(query.pairs().into_iter().filter(|(k, _)| pinned || k != "from"));
            let mut api: Vec<(String, String)> = vec![("group_by".into(), dimension.name.into())];
            if !then.is_empty() {
                api.push(("then".into(), then.join(",")));
            }
            api.extend(query.pairs());
            let api = api
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            let then_labels = then
                .iter()
                .filter_map(|t| insights::dimensions().find(|d| d.name == *t))
                .map(|d| d.label)
                .collect::<Vec<_>>();
            let then_label = match then_labels.as_slice() {
                [] => String::new(),
                [first, rest @ ..] if !rest.is_empty() => {
                    format!("{first} and {}", rest.join(" and ").to_lowercase())
                }
                [one, ..] => (*one).to_string(),
            };
            let cost_label = if all.estimated_usd > 0.0 {
                format!("cost, {} of it estimated", money_est(all.estimated_usd))
            } else {
                "cost".into()
            };
            Ok(ok(json!({
                "lead": format!("{}{filtered}", window.3),
                "window": window.0,
                // Three figures, as the design system's Stat allows: tokens, errors and latency are in the chart and
                // the ranking.
                "stats": [
                    { "figure": count(all.requests), "label": "requests" },
                    { "figure": money(all.cost_usd), "label": cost_label },
                    { "figure": count(all.refused), "label": "refused" },
                ],
                "metric": metric.0,
                "metrics": METRICS.iter().map(|m| json!({ "name": m.0, "label": m.1 })).collect::<Vec<_>>(),
                "chart_title": format!(
                    "{}, per {}{}",
                    metric.1,
                    if window.2 { "hour" } else { "day" },
                    trend.as_ref().map_or(String::new(), |(d, v)| format!(", {} {v}", d.label.to_lowercase()))
                ),
                "chart": chart,
                "trend": trend.as_ref().map(|(d, v)| json!({ "name": d.name, "value": v, "label": format!("{} {v}", d.label) })),
                "by": dimension.name,
                "ranking_title": format!("By {}, most costly first", dimension.label.to_lowercase()),
                "by_label": dimension.label,
                "bys": up_front,
                "more": more,
                "ranking": ranking,
                "then": then.join(","),
                "then_label": then_label,
                "est_tip": EST_TIP,
                "link": href("#/usage", &view),
                "agent": agent_prompt(&crate::base(), &api, &dimension.label.to_lowercase(), &then_label),
                "forecasts": forecasts(&console, &admin, now).await,
            })))
        }
        .await,
    )
}

/// Subscription use a budget did not count, said beside it: what the gateway enforces is what the meter shows.
pub(crate) fn uncounted_note(uncounted: f64) -> String {
    if uncounted > 0.0 {
        format!(
            " Beside it, {} of subscription use (an estimate at API prices) is not counted against the budget: its rule does not count subscription use at API prices.",
            money_est(uncounted)
        )
    } else {
        String::new()
    }
}

/// One budget a forecast is made for: whose it is, which requests it counts, and where it is set.
struct Gauge {
    /// Who it is for, as the forecast names it: `team payments`, `lee.k's key`, `customer acme`.
    label: String,
    budget: Budget,
    /// The dimension it counts by, and the values of it it counts. `*` counts each value on its own, and the
    /// forecast follows whichever is heading out first. No dimension counts everything (`global: true`).
    dimension: &'static str,
    values: Vec<String>,
    /// A `limits:` entry confined to one organization.
    org: Option<String>,
    /// Where it is set, the first words of its note.
    source: String,
    /// How a request it refused is told apart.
    refuses: Refuses,
}

/// What a budget's refusal record says of it: its code, and the `applied` limit the gateway wrote on it.
enum Refuses {
    /// A rule's budget, by the rule's name.
    Rule(String),
    /// A key's own budget, by the key's hash prefix.
    Key(String),
    /// A `limits:` entry, by its label (`limits { team: search } (line 21)`).
    Entry(String),
}

impl Refuses {
    fn refused(&self, row: &insights::Row) -> bool {
        let applied =
            serde_json::from_str::<Value>(&row.line).unwrap_or_default()["applied"].take();
        let (of, source) = (applied["of"].as_str(), applied["source"].as_str());
        match self {
            // Records from before `applied` was written name the rule alone.
            Refuses::Rule(name) => {
                row.code == "budget_exceeded"
                    && row.rule == *name
                    && of.is_none_or(|of| of == "rule")
            }
            Refuses::Key(key) => {
                row.code == "key_budget_exceeded"
                    && row.label("key") == key
                    && source.is_none_or(|s| s.ends_with("(keys file)"))
            }
            Refuses::Entry(label) => {
                ["budget_exceeded", "key_budget_exceeded"].contains(&row.code.as_str())
                    && source == Some(label.as_str())
            }
        }
    }
}

/// Every budget of the policy, as the gateway counts them (`Policy::applied`): each rule's budget, each key's own
/// budget from the keys file, and each entry of the `limits:` list.
fn gauges(policy: &Policy) -> Vec<Gauge> {
    let mut out = Vec::new();
    for rule in policy.rule_list() {
        // A budget for some models only counts in a counter of its own; the page has room for the one that counts
        // every model.
        let Some(budget) = rule.limits.budget() else {
            continue;
        };
        let (label, dimension, value) = match &rule.who {
            Who::Team(team) => (format!("team {team}"), "team", team.clone()),
            Who::Name(name) => (name.clone(), "person", name.clone()),
            // A budget for each person (of every key, or of the keys with a tag).
            Who::Any | Who::Tag(_) => ("each person".into(), "person", "*".into()),
        };
        out.push(Gauge {
            label,
            budget,
            dimension,
            values: vec![value],
            org: None,
            source: format!("Rule {}.", rule.name),
            refuses: Refuses::Rule(rule.name.clone()),
        });
    }
    let mut keyed: Vec<Gauge> = policy
        .entries()
        .filter_map(|(_, p)| {
            Some(Gauge {
                label: format!("{}'s key", p.name),
                budget: p.budget?,
                dimension: "key",
                values: vec![p.key.clone()],
                org: None,
                source: "The key's own budget, from the keys file.".into(),
                refuses: Refuses::Key(p.key.clone()),
            })
        })
        .collect();
    keyed.sort_by(|a, b| a.label.cmp(&b.label));
    out.extend(keyed);
    for entry in policy.scope_limits() {
        let (dimension, values, label) = match entry.kind {
            ScopeKind::Global => ("", Vec::new(), "everything".to_string()),
            // A group counts every model in it together.
            ScopeKind::ModelGroup => (
                "model_group",
                policy
                    .model_groups()
                    .iter()
                    .find(|(group, _)| *group == entry.name)
                    .map(|(_, members)| members.clone())
                    .unwrap_or_default(),
                format!("model group {}", entry.name),
            ),
            kind => {
                let word = kind.word();
                let label = if word == "person" {
                    entry.name.clone()
                } else {
                    format!("{word} {}", entry.name)
                };
                (word, vec![entry.name.clone()], label)
            }
        };
        // `{ org: acme }` names its organization by its name, not as a confinement.
        let org = entry.org.clone().filter(|_| entry.kind != ScopeKind::Org);
        for budget in &entry.budgets {
            out.push(Gauge {
                label: label.clone(),
                budget: *budget,
                dimension,
                values: values.clone(),
                org: org.clone(),
                source: format!("Set by {}.", entry.label()),
                refuses: Refuses::Entry(entry.label()),
            });
        }
    }
    out
}

/// Each budget in the policy, what it spent this period, and when it runs out at the pace it has spent at: every
/// scope, the closest to its limit first. An empty list means the policy sets no budget; no policy that loads gives
/// no forecasts at all.
async fn forecasts(console: &Console, admin: &Admin, now: u64) -> Value {
    let Ok(loaded) = config::load(&console.config().policy, Some(&console.config().keys)) else {
        return Value::Null;
    };
    let gauges = gauges(&loaded.policy);
    // Each budget over its own window (`per:` and `tz:`), as the gateway counts it. With a store the sums come from
    // SQL over every request of the window; the local chain is folded once, from the earliest window's start.
    let now_i = i64::try_from(now).unwrap_or(i64::MAX);
    let windows: Vec<(u64, u64)> = gauges
        .iter()
        .map(|g| {
            let (start, end) = g.budget.per.window(now_i);
            (
                u64::try_from(start).unwrap_or_default(),
                u64::try_from(end).unwrap_or_default(),
            )
        })
        .collect();
    let since = |start: u64, org: &Option<String>| {
        let mut query = Query {
            from: at(start),
            ..Query::default()
        };
        if let Some(org) = org {
            query.labels.push(("org".into(), org.clone()));
        }
        scoped(admin, &mut query);
        query
    };
    let index = insights::attached(&console.config().audit).index;
    let local = match &index {
        Some(_) => Vec::new(),
        None if gauges.is_empty() => Vec::new(),
        None => {
            let earliest = windows.iter().map(|w| w.0).min().unwrap_or(now);
            let mut query = since(earliest, &None);
            query.limit = insights::MAX_ROWS;
            rows(console, &query).await.unwrap_or_default()
        }
    };
    // The budget refusals of the longest window, told apart per budget below.
    let refusals: Vec<insights::Row> = {
        let earliest = windows.iter().map(|w| w.0).min().unwrap_or(now);
        let mut query = since(earliest, &None);
        query.outcome = "refused".into();
        query.limit = insights::MAX_ROWS;
        let found = match &index {
            Some(index) if !gauges.is_empty() => index.rows(&query).await.unwrap_or_default(),
            Some(_) => Vec::new(),
            None => local.iter().filter(|r| query.matches(r)).cloned().collect(),
        };
        found
            .into_iter()
            .filter(|r| r.code.ends_with("budget_exceeded"))
            .collect()
    };
    // Budgets of the same window, dimension and organization read the same sums: counted and not counted, by value.
    type Sums = BTreeMap<String, (f64, f64)>;
    let mut sums: HashMap<(u64, &str, Option<String>), Sums> = HashMap::new();
    let mut out: Vec<(bool, u32, Value)> = Vec::new();
    for (gauge, (start, end)) in gauges.iter().zip(windows) {
        // Everything is the sum over every model: each request that cost anything has one. A group sums its models.
        let dimension = match gauge.dimension {
            "" | "model_group" => "model",
            other => other,
        };
        let key = (start, dimension, gauge.org.clone());
        if !sums.contains_key(&key) {
            let query = since(start, &gauge.org);
            let found = match &index {
                Some(index) => index.spent(&query, dimension).await.unwrap_or_default(),
                None => {
                    let rows: Vec<insights::Row> =
                        local.iter().filter(|r| query.matches(r)).cloned().collect();
                    insights::spent(&rows, dimension, start)
                }
            };
            sums.insert(
                key.clone(),
                found
                    .into_iter()
                    .map(|(k, counted, uncounted)| (k, (counted, uncounted)))
                    .collect(),
            );
        }
        let by = sums.get(&key).cloned().unwrap_or_default();
        let add = |a: (f64, f64), b: &(f64, f64)| (a.0 + b.0, a.1 + b.1);
        let (label, (spent, uncounted)) = if gauge.dimension.is_empty() {
            (gauge.label.clone(), by.values().fold((0.0, 0.0), add))
        } else if gauge.values.first().is_some_and(|v| v == "*") {
            // Each one on its own: the one heading out first.
            let kind = gauge.dimension;
            by.into_iter()
                .max_by(|a, b| a.1.0.total_cmp(&b.1.0))
                .map_or((format!("each {kind}"), (0.0, 0.0)), |(v, s)| {
                    let v = if kind == "person" {
                        v
                    } else {
                        format!("{kind} {v}")
                    };
                    (format!("{v} (each {kind})"), s)
                })
        } else if gauge.dimension == "model_group" {
            let hits = by
                .iter()
                .filter(|(model, _)| gauge.values.iter().any(|m| config::model_matches(m, model)));
            (
                gauge.label.clone(),
                hits.map(|(_, s)| s).fold((0.0, 0.0), add),
            )
        } else {
            let one = gauge.values.first().map(String::as_str).unwrap_or_default();
            (
                gauge.label.clone(),
                by.get(one).copied().unwrap_or_default(),
            )
        };
        let label = match &gauge.org {
            Some(org) => format!("{label} in org {org}"),
            None => label,
        };
        let budget = gauge.budget;
        let pace = insights::pace(spent, budget.usd, start, now, end);
        let note = match pace {
            Pace::Idle => "Nothing spent yet this period.".to_string(),
            Pace::Spent => "Spent. Refused until the period resets.".to_string(),
            Pace::Lasts => "At this pace it lasts the period.".to_string(),
            Pace::RunsOut(at_secs) => format!(
                "At this pace it runs out at {} UTC.",
                time_list(&at(at_secs))
            ),
        };
        let percent = if budget.usd > 0.0 {
            (spent / budget.usd * 100.0).round().min(100.0) as u32
        } else {
            0
        };
        let from = at(start);
        let refused = refusals
            .iter()
            .filter(|r| r.time >= from && gauge.refuses.refused(r))
            .count();
        // A budget that lasts can still refuse: a request reserves its most output tokens' cost before it is sent,
        // and is refused when that would pass what is left. That is a budget spent for its callers.
        let refused_note = match refused {
            0 => String::new(),
            n => format!(
                " Refused {} this period: each request reserves what its most output tokens could cost before it is sent. Lower max output tokens (max_tokens) on the callers, or raise the budget.",
                enterplace_core::count(n, "request")
            ),
        };
        let over = matches!(pace, Pace::Spent | Pace::RunsOut(_)) || refused > 0;
        out.push((
            over,
            percent,
            json!({
                "label": label,
                "text": format!("{} of {} per {}", money(spent), money(budget.usd), budget.per.describe()),
                "percent": percent,
                "over": over,
                "note": format!("{} {note}{refused_note}{}", gauge.source, uncounted_note(uncounted)),
            }),
        ));
    }
    // Who is close to a limit comes first: spent or running out, then the most used.
    out.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    Value::Array(out.into_iter().map(|(_, _, v)| v).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_scale_tops_out_at_a_round_figure() {
        for (x, top) in [
            (124.0, 150.0),
            (0.63, 0.8),
            (3.0, 3.0),
            (8951.0, 10_000.0),
            (1.0, 1.0),
        ] {
            assert!((super::nice_top(x) - top).abs() < 1e-9, "{x}");
        }
    }
}
