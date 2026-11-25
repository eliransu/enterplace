//! Teams in the console app (`/console/app/#/teams`): who is in each team (the people and workloads whose keys name
//! it, admins marked), the rule that decides for its members and its budget. Read only: a team comes with a key, so
//! the way to add one is Issue a key on the People page.

use std::collections::BTreeMap;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, Uri},
    response::Response,
    routing::get,
};
use enterplace_core::{
    config,
    policy::{Permission, Principal, Who},
};
use serde_json::{Value, json};

use crate::{
    Console, Form,
    api::{answer, ok, signed_in},
    figures::money,
    redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links land there, with the query they carried.
        .route("/teams", get(|uri: Uri| async move { moved(&uri) }))
        .route("/api/teams", get(list))
}

fn moved(uri: &Uri) -> Response {
    let query = Form::of(uri);
    let kept: Vec<String> = query
        .pairs()
        .map(|(k, v)| format!("{}={}", crate::html::enc(k), crate::html::enc(v)))
        .collect();
    let mut to = "/console/app/#/teams".to_string();
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

/// What one limits: entry caps, as the Limits table says it: "$500 a month", "300 tokens per day".
fn limit_words(entry: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(b) = entry.get("budget").and_then(Value::as_object) {
        let usd = b.get("usd").and_then(Value::as_f64).unwrap_or(0.0);
        let per = b.get("per").and_then(Value::as_str).unwrap_or("window");
        out.push(format!("{} a {per}", money(usd)));
    }
    if let Some(rate) = entry.get("rate").and_then(Value::as_object) {
        for (key, words) in [
            ("rpm", "requests per minute"),
            ("rph", "requests per hour"),
            ("rpd", "requests per day"),
            ("tpm", "tokens per minute"),
            ("tpd", "tokens per day"),
        ] {
            if let Some(n) = rate.get(key) {
                out.push(format!("{n} {words}"));
            }
        }
    }
    if let Some(n) = entry.get("parallel") {
        out.push(format!("{n} requests in flight"));
    }
    out
}

async fn list(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let issue = admin.may(Permission::IssueKeys);
            let c = console.config();
            let loaded = match config::load(&c.policy, Some(&c.keys)) {
                Ok(loaded) => loaded,
                Err(problems) => {
                    return Ok(ok(json!({
                        "issue": issue,
                        "error": format!("The policy did not load: {} Open the raw policy to fix it.", problems.join(" ")),
                    })));
                }
            };
            let mut teams: BTreeMap<&str, Vec<(&str, bool)>> = BTreeMap::new();
            for (_, who) in loaded
                .policy
                .entries()
                .filter(|(_, w)| admin.covers(&w.org, &w.team, w.customer.as_deref()))
            {
                teams
                    .entry(who.team.as_str())
                    .or_default()
                    .push((who.name.as_str(), who.admin));
            }
            // Teams the policy lists show even before their first key, to those who see every team or this one.
            for team in loaded.policy.teams() {
                if !admin.confined() || admin.teams.contains(&team.name) {
                    teams.entry(team.name.as_str()).or_default();
                }
            }
            // Only admin keys and no team the policy lists: a team comes with the first key that is not an admin's.
            let only_admins = teams
                .values()
                .all(|people| !people.is_empty() && people.iter().all(|(_, admin)| *admin));
            if teams.is_empty() || only_admins {
                let mut empty = crate::start::empty_json("Teams", &crate::base());
                // Someone who may not issue keys is offered the docs, not the action.
                if !issue && let Some(e) = empty.as_object_mut() {
                    e.remove("action");
                }
                return Ok(ok(json!({ "issue": issue, "teams": [], "empty": empty })));
            }
            // The limits: entries written for one team, which count beside its rule's budget.
            let tree = config::policy_text(&c.policy)
                .ok()
                .and_then(|t| enterplace_core::versions::tree(&t).ok())
                .unwrap_or_default();
            let limits: Vec<&serde_json::Map<String, Value>> = tree
                .get("limits")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_object)
                .collect();
            let mut rows = Vec::new();
            for (team, people) in &mut teams {
                people.sort_unstable();
                people.dedup();
                // The rule that decides for the team's members, as the policy reads it: the first that names the
                // team or everyone. A rule naming one person may come before it for that person.
                let probe = Principal {
                    team: (*team).to_string(),
                    ..Default::default()
                };
                let rule = loaded.policy.rule_for(&probe);
                let mut budget: Vec<String> = rule
                    .and_then(|r| r.limits.budget())
                    .map(|b| format!("{} a {}", money(b.usd), b.per.describe()))
                    .into_iter()
                    .collect();
                for entry in limits
                    .iter()
                    .filter(|l| l.get("team").and_then(Value::as_str) == Some(*team))
                {
                    budget.extend(limit_words(entry));
                }
                let budget = if budget.is_empty() {
                    "none".to_string()
                } else {
                    budget.join(", ")
                };
                let rule = rule.map_or_else(
                    || "none: refused".to_string(),
                    |r| match &r.who {
                        Who::Team(_) => r.name.clone(),
                        _ => format!("{} (everyone)", r.name),
                    },
                );
                let owner = loaded
                    .policy
                    .teams()
                    .iter()
                    .find(|t| t.name == *team)
                    .and_then(|t| t.owner.clone());
                rows.push(json!({
                    "name": team,
                    "keys": enterplace_core::count(people.len(), "key"),
                    "owner": owner,
                    "people": people.iter().map(|(name, admin)| json!({ "name": name, "admin": admin })).collect::<Vec<Value>>(),
                    "rule": rule,
                    "budget": budget,
                }));
            }
            Ok(ok(json!({ "issue": issue, "teams": rows, "empty": null })))
        }
        .await,
    )
}
