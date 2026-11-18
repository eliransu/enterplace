//! Analytics in the console app (`/console/app/#/analytics`): requests, cost and refusals over a window, one chart
//! with a metric switch, a ranking by any dimension, and each budget's forecast at the pace it has spent at.
//!
//! Rows come from the store's index when the gateway has one (every replica), else from the local chain. Everything a
//! test pins (money, latency, the lead line, the empty state, which breakdowns are offered) is worded here, so the app
//! only lays it out.

use std::collections::BTreeMap;

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
    policy::{Permission, Who},
};
use serde_json::{Value, json};

use crate::{
    Admin, Console, Form,
    api::{Fail, answer, ok, signed_in},
    figures::{money, time_list},
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
        Some(query) => redirect(&format!("/console/app/#/analytics?{query}")),
        None => redirect("/console/app/#/analytics"),
    }
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
                        "Your role, {}, does not have the {} permission this page needs. Ask a Enterplace admin to add it to the role under roles: in the policy.",
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
            if query.from.is_empty() {
                query.from = at(now.saturating_sub(window.1));
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

            // Every hour or day of the window, empty ones too, so the bars keep time.
            let had: BTreeMap<String, Stats> = summed.series.into_iter().collect();
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
                let top = if top > 0.0 { top } else { 1.0 };
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
            let ranking: Vec<Value> = summed
                .ranking
                .iter()
                .take(25)
                .map(|(value, s)| {
                    json!({
                        "value": if value.is_empty() { "(none)" } else { value.as_str() },
                        "href": href("/console/requests", &with(&Query::default(), dimension.name, value)),
                        "requests": count(s.requests),
                        "refused": count(s.refused),
                        "errors": count(s.errors),
                        "tokens": count(s.input_tokens + s.output_tokens),
                        "usd": money(s.cost_usd),
                        "p50": pct(s, 50.0),
                        "p95": pct(s, 95.0),
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
            Ok(ok(json!({
                "lead": format!("Over {}.{filtered}", window.3),
                "window": window.0,
                // Three figures, as the design system's Stat allows: tokens, errors and latency are in the chart and
                // the ranking.
                "stats": [
                    { "figure": count(all.requests), "label": "requests" },
                    { "figure": money(all.cost_usd), "label": "cost" },
                    { "figure": count(all.refused), "label": "refused" },
                ],
                "metric": metric.0,
                "metrics": METRICS.iter().map(|m| json!({ "name": m.0, "label": m.1 })).collect::<Vec<_>>(),
                "chart_title": format!("{}, per {}", metric.1, if window.2 { "hour" } else { "day" }),
                "chart": chart,
                "by": dimension.name,
                "ranking_title": format!("By {}, most costly first", dimension.label.to_lowercase()),
                "by_label": dimension.label,
                "bys": up_front,
                "more": more,
                "ranking": ranking,
                "forecasts": forecasts(&console, &admin, now).await,
            })))
        }
        .await,
    )
}

/// Each budget in the policy, what it spent this period, and when it runs out at the pace it has spent at. An empty
/// list means the policy sets no budget; no policy that loads gives no forecasts at all.
async fn forecasts(console: &Console, admin: &Admin, now: u64) -> Value {
    let Ok(loaded) = config::load(&console.config().policy, Some(&console.config().keys)) else {
        return Value::Null;
    };
    let budgets: Vec<_> = loaded
        .policy
        .rule_list()
        .iter()
        .filter_map(|r| r.limits.budget().map(|b| (r, b)))
        .collect();
    // Each budget over its own window (`per:` and `tz:`), as the gateway counts it. With a store the sums come from
    // SQL over every request of the window; the local chain is folded once, from the earliest window's start.
    let now_i = i64::try_from(now).unwrap_or(i64::MAX);
    let windows: Vec<(u64, u64)> = budgets
        .iter()
        .map(|(_, b)| {
            let (start, end) = b.per.window(now_i);
            (
                u64::try_from(start).unwrap_or_default(),
                u64::try_from(end).unwrap_or_default(),
            )
        })
        .collect();
    let since = |start: u64| {
        let mut query = Query {
            from: at(start),
            ..Query::default()
        };
        scoped(admin, &mut query);
        query
    };
    let index = insights::attached(&console.config().audit).index;
    let local = match &index {
        Some(_) => Vec::new(),
        None if budgets.is_empty() => Vec::new(),
        None => {
            let earliest = windows.iter().map(|w| w.0).min().unwrap_or(now);
            let mut query = since(earliest);
            query.limit = insights::MAX_ROWS;
            rows(console, &query).await.unwrap_or_default()
        }
    };
    let mut out: Vec<Value> = Vec::new();
    for ((rule, budget), (start, end)) in budgets.into_iter().zip(windows) {
        let dimension = match &rule.who {
            Who::Team(_) => "team",
            Who::Name(_) | Who::Any | Who::Tag(_) => "person",
        };
        let by: BTreeMap<String, f64> = match &index {
            Some(index) => index
                .spent(&since(start), dimension)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect(),
            None => insights::spent(&local, dimension, start)
                .into_iter()
                .collect(),
        };
        let (label, spent) = match &rule.who {
            Who::Team(team) => (
                format!("team {team}"),
                by.get(team.as_str()).copied().unwrap_or_default(),
            ),
            Who::Name(name) => (
                name.clone(),
                by.get(name.as_str()).copied().unwrap_or_default(),
            ),
            // A budget for each person (of every key, or of the keys with a tag): the one heading out first.
            Who::Any | Who::Tag(_) => by
                .into_iter()
                .max_by(|a, b| a.1.total_cmp(&b.1))
                .map_or(("each person".into(), 0.0), |(p, s)| {
                    (format!("{p} (each person)"), s)
                }),
        };
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
        out.push(json!({
            "label": label,
            "text": format!("{} of {} per {}", money(spent), money(budget.usd), budget.per.describe()),
            "percent": percent,
            "over": matches!(pace, Pace::Spent | Pace::RunsOut(_)),
            "note": format!("Rule {}. {note}", rule.name),
        }));
    }
    Value::Array(out)
}
