//! Spend in the console app (`/console/app/#/usage/spend`): this month's spend (UTC) from the usage records, per day, per
//! person and per model, against every budget of the policy and every key's own budget.
//!
//! Everything a test pins (money, the lead, each meter's note, the chart's scale and caption) is worded here; the
//! app only lays it out. The page is read only: a budget changes in the policy.

use std::collections::{BTreeSet, HashMap};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
};
use enterplace_core::{
    config::{self, Loaded},
    policy::{Period, Permission, Who},
};
use serde_json::{Value, json};

use crate::{
    Console,
    api::{Fail, answer, ok, signed_in},
    figures::money,
    html::thousands,
    pages::{MONTHS, days_in, price_word, today},
    records_for, redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links and bookmarks land there.
        .route(
            "/spend",
            get(|| async { redirect("/console/app/#/usage/spend") }),
        )
        .route("/api/spend", get(spend))
}

async fn spend(State(console): State<Console>, headers: HeaderMap) -> Response {
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
            let config = console.config();
            // ponytail: the whole audit log is read on every request, as the audit page does.
            let log = records_for(&admin, &config.audit);
            let loaded = config::load(&config.policy, Some(&config.keys));
            Ok(ok(view(&log, &loaded)))
        }
        .await,
    )
}

/// The smallest of 1, 2, 5 or 10 times a power of ten that is at least `x`: the top of a chart's scale.
fn nice_top(x: f64) -> f64 {
    if x <= 0.0 || !x.is_finite() {
        return 1.0;
    }
    let power = 10f64.powf(x.log10().floor());
    [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .map(|m| m * power)
        .find(|top| *top >= x * 0.999_999)
        .unwrap_or(10.0 * power)
}

/// Spent, requests and tokens of one model or person.
#[derive(Default)]
struct Tally {
    usd: f64,
    requests: usize,
    tokens: u64,
}

/// One budget of the policy, with what was spent against it in its current period.
struct Meter {
    label: String,
    rule_line: usize,
    usd: f64,
    per_day: bool,
    spent: f64,
    /// The time of the record that took spend to the budget, if one did.
    ran_out: Option<String>,
    /// The rule that sets it, or for a key's own budget the key's hash prefix.
    rule: String,
    key: Option<String>,
    /// Requests it refused in its current period.
    refused: usize,
}

fn s<'a>(record: &'a Value, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

fn link(label: &str, href: &str) -> Value {
    json!({ "label": label, "href": href })
}

/// The Spend page, from the usage records of this month (UTC) and the budgets of the policy.
fn view(log: &Result<Option<String>, String>, loaded: &Result<Loaded, Vec<String>>) -> Value {
    let today = today();
    let part = |range: std::ops::Range<usize>| {
        today
            .get(range)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(1)
    };
    let (year, month, day_now) = (part(0..4), part(5..7).clamp(1, 12), part(8..10) as usize);
    let this_month = today.get(..7).unwrap_or("");
    let days = days_in(year, month);
    let name = MONTHS[month as usize - 1];
    let next = format!("1 {}", MONTHS[month as usize % 12]);
    let lead_none = "What each team spends, by model.";
    let text = match log {
        Ok(text) => text.as_deref().unwrap_or(""),
        Err(err) => {
            return json!({
                "lead": lead_none,
                "error": format!("The audit log did not load: {err} Spend is read from it, so this page shows it again once the log can be read."),
            });
        }
    };
    let rules = loaded
        .as_ref()
        .map(|l| l.policy.rule_list())
        .unwrap_or_default();
    let mut meters: Vec<(Meter, Who)> = rules
        .iter()
        .filter_map(|rule| {
            let budget = rule.limits.budget()?;
            let label = match &rule.who {
                Who::Team(team) => team.clone(),
                Who::Name(name) => name.clone(),
                Who::Tag(tag) => format!("tag {tag}"),
                Who::Any => String::new(),
            };
            Some((
                Meter {
                    label,
                    rule_line: rule.line,
                    usd: budget.usd,
                    per_day: budget.per == Period::Day,
                    spent: 0.0,
                    ran_out: None,
                    rule: rule.name.clone(),
                    key: None,
                    refused: 0,
                },
                rule.who.clone(),
            ))
        })
        .collect();
    // A key's own budget, from the keys file, after the rules' budgets. `Who::Any` is a placeholder: a key meter
    // counts by its hash.
    let mut keyed: Vec<(Meter, Who)> = loaded
        .as_ref()
        .map(|l| {
            l.policy
                .entries()
                .filter_map(|(_, p)| {
                    let budget = p.budget?;
                    Some((
                        Meter {
                            label: format!("{}'s key", p.name),
                            rule_line: 0,
                            usd: budget.usd,
                            per_day: budget.per == Period::Day,
                            spent: 0.0,
                            ran_out: None,
                            rule: String::new(),
                            key: Some(p.key.clone()),
                            refused: 0,
                        },
                        Who::Any,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    keyed.sort_by(|a, b| a.0.label.cmp(&b.0.label));
    meters.extend(keyed);
    // A budget for everyone is per person: the meter follows whoever has spent most against it.
    let mut each: HashMap<(usize, String), f64> = HashMap::new();

    let (mut total, mut unknown, mut stopped) = (0.0, 0usize, 0usize);
    let mut daily = vec![0.0; days];
    let mut models: HashMap<String, (String, Tally)> = HashMap::new();
    let mut sources: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut people: HashMap<String, (Tally, HashMap<String, f64>)> = HashMap::new();
    for line in text.lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let time = s(&record, "time");
        if time.get(..7) != Some(this_month) {
            continue;
        }
        let today_only = time.get(..10) == Some(today.as_str());
        if s(&record, "event") != "usage" {
            stopped += usize::from(s(&record, "verdict") == "refused");
            for (meter, _) in &mut meters {
                let mine = match &meter.key {
                    Some(key) => {
                        s(&record, "code") == "key_budget_exceeded" && s(&record, "key") == key
                    }
                    None => {
                        s(&record, "code") == "budget_exceeded" && s(&record, "rule") == meter.rule
                    }
                };
                meter.refused += usize::from(mine && (today_only || !meter.per_day));
            }
            continue;
        }
        let usd = record["charged_usd"].as_f64().unwrap_or_default();
        let count = |key: &str| record[key].as_u64().unwrap_or_default();
        let tokens = count("input_tokens")
            + count("output_tokens")
            + count("cache_read_tokens")
            + count("cache_write_tokens");
        unknown += usize::from(record["cost_usd"].is_null());
        total += usd;
        let day: usize = time.get(8..10).and_then(|d| d.parse().ok()).unwrap_or(1);
        if let Some(slot) = daily.get_mut(day.saturating_sub(1)) {
            *slot += usd;
        }
        let (model, person, team) = (
            s(&record, "model"),
            s(&record, "person"),
            s(&record, "team"),
        );
        let entry = models
            .entry(model.to_string())
            .or_insert_with(|| (s(&record, "provider").to_string(), Tally::default()));
        entry.1.usd += usd;
        entry.1.requests += 1;
        entry.1.tokens += tokens;
        // Records written before price_source existed say nothing of it, and a null one had no price.
        let source = match (s(&record, "price_source"), record["cost_usd"].is_null()) {
            ("", true) => "none",
            (source, _) => source,
        };
        if !source.is_empty() {
            sources
                .entry(model.to_string())
                .or_default()
                .insert(source.to_string());
        }
        let who = people.entry(person.to_string()).or_default();
        who.0.usd += usd;
        who.0.requests += 1;
        *who.1.entry(model.to_string()).or_default() += usd;
        for (i, (meter, rule_who)) in meters.iter_mut().enumerate() {
            if meter.per_day && !today_only {
                continue;
            }
            let spent = match (&meter.key, rule_who) {
                (Some(key), _) if s(&record, "key") == key => {
                    meter.spent += usd;
                    meter.spent
                }
                (Some(_), _) => continue,
                (None, rule_who) => match rule_who {
                    Who::Team(t) if t == team => {
                        meter.spent += usd;
                        meter.spent
                    }
                    Who::Name(n) if n == person => {
                        meter.spent += usd;
                        meter.spent
                    }
                    Who::Any => {
                        let spent = each.entry((i, person.to_string())).or_default();
                        *spent += usd;
                        if *spent > meter.spent || meter.label.is_empty() {
                            meter.spent = *spent;
                            meter.label = person.to_string();
                        }
                        *spent
                    }
                    _ => continue,
                },
            };
            if spent >= meter.usd && meter.ran_out.is_none() {
                meter.ran_out = Some(time.to_string());
            }
        }
    }

    if total == 0.0 && meters.is_empty() && loaded.is_ok() {
        // Requests that cost nothing (the demo model) would draw an empty chart and rank people at $0: one line says it.
        let empty = if people.is_empty() && stopped == 0 {
            crate::start::empty_for("Spend", &crate::base()).map(|e| {
                json!({
                    "title": e.title,
                    "body": e.body,
                    "action": link(e.action.0, e.action.1),
                    "docs": format!("{}{}", crate::start::DOCS, e.docs),
                    "lines": crate::start::BUDGET_LINES,
                })
            })
        } else {
            Some(json!({
                "title": "No spend yet",
                "body": if models.is_empty() {
                    "No request reached a provider yet."
                } else if models.keys().all(|m| m == enterplace_core::usage::DEMO_MODEL) {
                    "Demo requests are free."
                } else {
                    "No request so far had a price."
                },
                "action": link("Add a budget", "/console/start?track=limit#step-5"),
            }))
        };
        return json!({ "lead": lead_none, "empty": empty });
    }

    let at = |time: &str| {
        let day: usize = time.get(8..10).and_then(|d| d.parse().ok()).unwrap_or(1);
        (day, time.get(11..16).unwrap_or("").to_string())
    };
    // The lead: the month's total, who ran out, and who is on pace to.
    let mut lead = format!("{} spent in {name} so far.", money(total));
    let mut on_pace = Vec::new();
    for (meter, who) in &meters {
        if meter.label.is_empty() {
            continue;
        }
        // A sentence does not start with a lower-case identifier: a team is named as one.
        let whose = if matches!(who, Who::Team(_)) {
            format!("Team {}", meter.label)
        } else {
            meter.label.clone()
        };
        match &meter.ran_out {
            Some(time) => {
                let until = if meter.per_day {
                    "tomorrow".to_string()
                } else {
                    next.clone()
                };
                lead.push_str(&format!(
                    " {whose} spent its {} on {} {name} and is refused until {until}.",
                    money(meter.usd),
                    at(time).0
                ));
            }
            None if !meter.per_day
                && meter.spent > 0.0
                && meter.usd / (meter.spent / day_now as f64) < days as f64 =>
            {
                on_pace.push(whose);
            }
            None => {}
        }
    }
    match on_pace.as_slice() {
        [] => {}
        [one] => lead.push_str(&format!(
            " {one} is on pace to run out before the month ends."
        )),
        [rest @ .., last] => {
            // Only the first name starts the sentence.
            let later = |w: &String| w.replacen("Team ", "team ", 1);
            let middle: Vec<String> = rest.iter().skip(1).map(later).collect();
            let first = rest.first().cloned().unwrap_or_default();
            let head = [first]
                .into_iter()
                .chain(middle)
                .collect::<Vec<_>>()
                .join(", ");
            lead.push_str(&format!(
                " {head} and {} are on pace to run out before the month ends.",
                later(last)
            ));
        }
    }
    let first_out = meters
        .iter()
        .filter_map(|(m, _)| m.ran_out.as_ref().map(|t| (t.clone(), m)))
        .filter(|(_, m)| !m.per_day && m.key.is_none())
        .min_by(|a, b| a.0.cmp(&b.0));
    let action = match &first_out {
        Some((_, meter)) => link(
            &format!("Edit the {} budget in the policy", meter.label),
            &format!("/console/policy?line={}", meter.rule_line),
        ),
        None if meters.is_empty() => Value::Null,
        None => link("Edit the budgets in the policy", "/console/policy"),
    };

    // The chart: one bar per day of the month, the pace that keeps every monthly budget inside its limit, and the
    // day the first budget ran out.
    let pace = meters
        .iter()
        .filter(|(m, who)| !m.per_day && !matches!(who, Who::Any) && m.key.is_none())
        .map(|(m, _)| m.usd)
        .sum::<f64>()
        / days as f64;
    let highest = daily.iter().copied().fold(0.0, f64::max);
    let top = nice_top(highest.max(pace));
    let mark = first_out.as_ref().map(|(time, _)| at(time).0);
    let shown = [1, 5, 10, 15, 20, 25, days];
    let bars: Vec<Value> = daily
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let day = i + 1;
            let future = i >= day_now;
            json!({
                "day": day,
                // Days still to come are an empty slot, so the month keeps its width.
                "percent": if future { Value::Null } else { json!((value / top * 1000.0).round() / 10.0) },
                "title": if future { String::new() } else { format!("{day} {name}: {}", money(*value)) },
                "label": shown.contains(&day) || Some(day) == mark,
                "mark": Some(day) == mark,
            })
        })
        .collect();
    let peak = daily
        .iter()
        .enumerate()
        .take(day_now)
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map_or(1, |(i, _)| i + 1);
    let later = if day_now < days {
        format!(" {} to {days} {name} have not happened yet.", day_now + 1)
    } else {
        String::new()
    };
    let label = format!(
        "Spend per day in {name}. The highest day is {peak} {name} at {}.{later}",
        money(daily.get(peak - 1).copied().unwrap_or_default())
    );
    let mut caption = if pace > 0.0 {
        let above = daily.iter().take(day_now).filter(|v| **v > pace).count();
        format!(
            "The dashed line is {} a day, the pace that keeps every monthly budget inside its limit. {} of the {} days so far {} above it.",
            money(pace),
            above,
            day_now,
            if above == 1 { "is" } else { "are" }
        )
    } else {
        format!("Each bar is one day of {name}, UTC.")
    };
    if let Some((time, meter)) = &first_out {
        caption.push_str(&format!(
            " The mark on {} {name} is when {} ran out.",
            at(time).0,
            meter.label
        ));
    }
    let chart = json!({
        "label": label,
        "caption": caption,
        "scale": [money(top), money(top / 2.0), money(0.0)],
        "pace": (pace > 0.0).then(|| (pace / top * 1000.0).round() / 10.0),
        "mark": mark,
        "days": bars,
    });

    // Who spent most, each with a way to their requests.
    let mut ranked: Vec<_> = people.iter().collect();
    // By spend, then by requests: until something is spent, the busiest come first.
    ranked.sort_by(|a, b| {
        b.1.0
            .usd
            .total_cmp(&a.1.0.usd)
            .then(b.1.0.requests.cmp(&a.1.0.requests))
            .then(a.0.cmp(b.0))
    });
    let spenders: Vec<Value> = ranked
        .iter()
        .take(3)
        .map(|(person, (tally, by_model))| {
            let mostly = by_model
                .iter()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .map_or("", |(m, _)| m.as_str());
            json!({
                "name": person,
                "sent": format!(
                    "Sent {} {}, {}",
                    thousands(tally.requests),
                    if tally.requests == 1 { "request" } else { "requests" },
                    money(tally.usd)
                ),
                // An identifier, shown whole: it never breaks at its dash.
                "mostly": mostly,
                "href": format!("/console/audit?q={}", crate::html::enc(person)),
            })
        })
        .collect();

    let budgets = if let Err(problems) = loaded {
        json!({ "problem": {
            "title": "The policy file has problems",
            "body": format!(
                "{} in the policy file, so its budgets cannot be shown here. Enterplace keeps using the version it has. Open the policy to fix them.",
                enterplace_core::count(problems.len(), "problem")
            ),
            "action": link("Open the policy", "/console/policy"),
        }})
    } else if meters.is_empty() {
        json!({ "problem": {
            "title": "No budgets yet",
            "body": format!(
                "Spend is being recorded: {} in {name} so far. Nothing stops it, because the policy sets no budget for any team.",
                money(total)
            ),
            "action": link("Add a budget to the policy", "/console/policy"),
        }})
    } else {
        let list: Vec<Value> = meters
            .iter()
            .map(|(meter, who)| meter_json(meter, who, &at, name, &next, day_now, days))
            .collect();
        json!({ "meters": list })
    };

    let mut by_model: Vec<(&String, &(String, Tally))> = models.iter().collect();
    by_model.sort_by(|a, b| b.1.1.usd.total_cmp(&a.1.1.usd).then(a.0.cmp(b.0)));
    let model_rows: Vec<Value> = by_model
        .iter()
        .map(|(model, (provider, t))| {
            let priced: Vec<String> = sources
                .get(*model)
                .into_iter()
                .flatten()
                .map(|source| match source.as_str() {
                    "none" => "no price, cost unknown".to_string(),
                    source => format!("priced {}", price_word(source)),
                })
                .collect();
            json!({
                "model": model,
                "usd": money(t.usd),
                "provider": provider,
                "priced": priced.join("; "),
                "requests": thousands(t.requests),
                "tokens": thousands(usize::try_from(t.tokens).unwrap_or(usize::MAX)),
            })
        })
        .collect();
    // Only the sources this month's answers were priced from, in the order a price is looked up.
    let used: BTreeSet<&str> = sources.values().flatten().map(String::as_str).collect();
    let named: Vec<&str> = [
        ("policy", "the prices section of the policy file"),
        (
            "builtin",
            "Enterplace's own table, checked against each provider's price list on 13 November 2026",
        ),
        (
            "litellm",
            "the LiteLLM table (MIT price map, pinned in this build)",
        ),
    ]
    .into_iter()
    .filter(|(key, _)| used.contains(key))
    .map(|(_, words)| words)
    .collect();
    let mut note = match named.as_slice() {
        [] => {
            "Prices: the policy file's prices, then Enterplace's own table, then the LiteLLM table."
                .to_string()
        }
        [one] => format!("Prices this month came from {one}."),
        many => format!(
            "Prices this month came from {} and {}.",
            many[..many.len() - 1].join(", "),
            many[many.len() - 1]
        ),
    };
    if unknown > 0 {
        note.push_str(&format!(
            " {} reported no usage or had no price: each counts as what it reserved against a budget, or nothing without one.",
            if unknown == 1 {
                "1 answer".to_string()
            } else {
                format!("{} answers", thousands(unknown))
            }
        ));
    }

    json!({
        "lead": lead,
        "action": action,
        "month": name,
        "chart": chart,
        "spenders": spenders,
        "budgets": budgets,
        "models": model_rows,
        // Refused requests reached no provider and cost nothing: a row of their own under the models.
        "stopped": thousands(stopped),
        "note": note,
    })
}

/// One budget's meter: what it spent of its limit, and when it runs out or why it refused.
fn meter_json(
    meter: &Meter,
    who: &Who,
    at: &dyn Fn(&str) -> (usize, String),
    name: &str,
    next: &str,
    day_now: usize,
    days: usize,
) -> Value {
    let pct = if meter.usd > 0.0 {
        (meter.spent / meter.usd * 100.0).round().min(100.0) as u32
    } else {
        0
    };
    let resets = if meter.per_day {
        "Resets at midnight UTC".to_string()
    } else {
        format!("Resets {next}")
    };
    let (note, over) = match &meter.ran_out {
        Some(time) => {
            let (day, clock) = at(time);
            let until = if meter.per_day {
                "midnight UTC".to_string()
            } else {
                format!("it resets on {next}")
            };
            (
                format!("Spent on {day} {name} at {clock}. Refused until {until}."),
                true,
            )
        }
        None if meter.per_day => (format!("{resets}."), false),
        None if meter.spent > 0.0 => {
            let runs_out = (meter.usd / (meter.spent / day_now as f64)) as usize + 1;
            if runs_out <= days {
                (
                    format!("At this rate it runs out around {runs_out} {name}. {resets}."),
                    false,
                )
            } else {
                (format!("At this rate it lasts the month. {resets}."), false)
            }
        }
        None => (format!("Nothing spent yet. {resets}."), false),
    };
    let note = match (&meter.key, who) {
        (Some(_), _) => format!("The key's own budget, from the keys file. {note}"),
        (None, Who::Any) => {
            format!("A budget for each person; the meter shows who has spent most. {note}")
        }
        _ => note,
    };
    // What the budget stopped, under its meter: the refusals are the reason to look.
    let note = match meter.refused {
        0 => note,
        n => format!(
            "{note} Refused {} {}.",
            enterplace_core::count(n, "request"),
            if meter.per_day { "today" } else { "this month" }
        ),
    };
    let label = if meter.label.is_empty() {
        "each person"
    } else {
        meter.label.as_str()
    };
    json!({
        "label": label,
        "text": format!("{} of {}{}", money(meter.spent), money(meter.usd), if meter.per_day { " today" } else { "" }),
        "percent": pct,
        // A budget that refused a request is spent, even when held reservations, not charges, filled it.
        "over": over || meter.refused > 0,
        "note": note,
    })
}
