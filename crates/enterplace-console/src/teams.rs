//! Groups (teams) in the console app (`/console/app/#/teams`): who is in each (the people and workloads whose keys
//! name it, admins marked), the rule that decides for its members and its budget; and the changes: create, rename and
//! delete a group, and move a person's key into or out of one. A key is in exactly one group, its `team`, so adding a
//! person moves their key here and removing them moves it to another group.

use std::collections::BTreeMap;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use enterplace_core::{
    config::{self, KeyEntry},
    keyfile, kill,
    policy::{Permission, Principal, Who},
    store, versions,
};
use serde_json::{Map, Value, json};

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED,
    api::{
        Fail, answer, bad, body_of, commit, current, name_ok, ok, remove_named, section, sentence,
        signed_in, text,
    },
    edit,
    figures::money,
    read_only, record, redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links land there, with the query they carried.
        .route("/teams", get(|uri: Uri| async move { moved(&uri) }))
        .route("/api/teams", get(list).post(create))
        .route("/api/teams/members", post(move_key))
        .route("/api/teams/rename", post(rename))
        .route("/api/teams/remove", post(remove))
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
            let manage = manages(&admin);
            let entries = entries(&console);
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
                return Ok(ok(
                    json!({ "issue": issue, "manage": manage, "teams": [], "empty": empty }),
                ));
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
                    "members": members(&entries, team),
                    "rule": rule,
                    "budget": budget,
                }));
            }
            Ok(ok(
                json!({ "issue": issue, "manage": manage, "teams": rows, "empty": null }),
            ))
        }
        .await,
    )
}

// ---------------------------------------------------------------- changes

/// Whether the person may create, rename and delete groups: change the policy and every key.
fn manages(admin: &Admin) -> bool {
    edit::edits_policy(admin) && admin.may(Permission::IssueKeys) && !admin.read_only
}

/// Every key in the keys file, or none when it cannot be read (the People page says why).
fn entries(console: &Console) -> Vec<KeyEntry> {
    let keys = &console.config().keys;
    store::attached(keys)
        .map(|s| s.keys_text())
        .or_else(|| config::read_keys(keys).ok().flatten())
        .and_then(|t| config::key_entries(keys, &t).ok())
        .unwrap_or_default()
}

fn service(entry: &KeyEntry) -> bool {
    entry.options.metadata.get("kind").map(String::as_str) == Some("workload")
}

/// The people in a group: its keys that are not an app's service key, by name.
fn members(entries: &[KeyEntry], team: &str) -> Vec<Value> {
    let mut people: Vec<&KeyEntry> = entries
        .iter()
        .filter(|e| e.team == team && !service(e))
        .collect();
    people.sort_by(|a, b| a.name.cmp(&b.name));
    people
        .iter()
        .map(|e| {
            let kind = match e.options.metadata.get("kind").map(String::as_str) {
                _ if e.admin => "admin key",
                Some(crate::PERSON_TOKEN_KIND) => "person token",
                _ => "key",
            };
            json!({ "name": e.name, "sha256": e.sha256, "hash": &e.sha256[..8], "kind": kind, "admin": e.admin })
        })
        .collect()
}

/// Whether there is a group `name`: a team some key names, or one the policy lists.
fn exists(console: &Console, entries: &[KeyEntry], name: &str) -> Result<bool, Fail> {
    let (text, _) = current(console)?;
    let tree = versions::tree(&text).map_err(|e| bad(sentence(&e)))?;
    Ok(entries.iter().any(|e| e.team == name) || listed(&tree, name))
}

fn listed(tree: &Map<String, Value>, name: &str) -> bool {
    tree.get("teams")
        .and_then(Value::as_array)
        .is_some_and(|t| {
            t.iter()
                .any(|t| t.get("name").and_then(Value::as_str) == Some(name))
        })
}

/// Renames team `from` to `to` (with `to` None, only finds it) wherever the policy names a team: every `team:` value
/// and every name in a `teams:` list, at any depth. Returns the top level sections that name it. The groups listed
/// under `teams:` are named by `name:`, so the caller renames the group itself.
fn rename_in(tree: &mut Map<String, Value>, from: &str, to: Option<&str>) -> Vec<String> {
    fn swap(s: &mut String, from: &str, to: Option<&str>) -> usize {
        if s != from {
            return 0;
        }
        if let Some(to) = to {
            *s = to.to_string();
        }
        1
    }
    fn walk(value: &mut Value, from: &str, to: Option<&str>) -> usize {
        match value {
            Value::Object(map) => map
                .iter_mut()
                .map(|(key, v)| match (key.as_str(), v) {
                    ("team", Value::String(s)) => swap(s, from, to),
                    ("teams", Value::Array(items)) => items
                        .iter_mut()
                        .map(|item| match item {
                            Value::String(s) => swap(s, from, to),
                            other => walk(other, from, to),
                        })
                        .sum(),
                    (_, other) => walk(other, from, to),
                })
                .sum(),
            Value::Array(items) => items.iter_mut().map(|i| walk(i, from, to)).sum(),
            _ => 0,
        }
    }
    tree.iter_mut()
        .filter_map(|(key, value)| (walk(value, from, to) > 0).then(|| key.clone()))
        .collect()
}

/// The kill switch that stops a whole team, if one does: its keys moved elsewhere would be let through.
fn stopped(console: &Console, team: &str) -> Result<(), Fail> {
    let kills = kill::read(&kill::path_beside(&console.config().keys)).unwrap_or_default();
    match kills.iter().find(|k| k.scope == "team" && k.value == team) {
        None => Ok(()),
        Some(k) => Err(bad(format!(
            "Traffic for group {team} is stopped ({}): a key moved out of it, or the group renamed, would be let through. Restore traffic for it on the People page first.",
            k.reason
        ))),
    }
}

async fn refuse(console: &Console, admin: &Admin, action: &'static str) -> Fail {
    read_only(console, admin, action).await;
    Fail(
        StatusCode::FORBIDDEN,
        "Your role may not change groups: it takes a role that may edit the policy and issue keys. Ask an admin.".into(),
    )
}

/// Moves keys of group `from` to group `team` in one step (the keys file in one write, the store in one
/// transaction), recorded first: all of them move, or none.
async fn move_keys(
    console: &Console,
    admin: &Admin,
    moving: &[&KeyEntry],
    from: &str,
    team: &str,
) -> Result<(), Fail> {
    let names: Vec<&str> = moving.iter().map(|e| e.name.as_str()).collect();
    let mut target = json!({ "name": names.join(", "), "team": from, "to": team });
    if let ([one], Value::Object(t)) = (moving, &mut target) {
        t.insert("sha256_prefix".into(), one.sha256[..8].into());
    }
    let act = Act {
        action: "move_key",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target,
    };
    if record(console, &act, None, None).await.is_err() {
        return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
    }
    let keys = console.config().keys.clone();
    let hashes: Vec<String> = moving.iter().map(|e| e.sha256.clone()).collect();
    let to = team.to_string();
    let done = tokio::task::spawn_blocking(move || keyfile::move_keys(&keys, &hashes, &to))
        .await
        .unwrap_or_else(|err| Err(format!("nothing was changed: {err}. Try again.")));
    let error = match done {
        Ok(true) => return Ok(()),
        Ok(false) => {
            "A key is no longer there: someone revoked or rotated it. Nothing was changed. Reload the page and try again.".to_string()
        }
        Err(err) => sentence(&err),
    };
    let _ = record(console, &act, Some("keys_file"), Some(&error)).await;
    Err(bad(error))
}

async fn create(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !manages(&admin) {
                return Err(refuse(&console, &admin, "add_team").await);
            }
            let body = body_of(&bytes)?;
            let name = text(&body, "name").to_string();
            name_ok(&name, "group", "design").map_err(bad)?;
            if exists(&console, &entries(&console), &name)? {
                return Err(bad(format!(
                    "There is a group named {name} already. Pick another name, or add people to that one."
                )));
            }
            let note = format!("Add group {name}");
            commit(&console, &admin, "add_team", note, json!({ "team": name }), |tree| {
                section(tree, "teams")?.push(json!({ "name": name }));
                Ok(())
            })
            .await
        }
        .await,
    )
}

/// Puts a person in group `name`, which moves their key out of the group it was in. Removing a person from a group
/// is putting them in another one: a key is always in one.
async fn move_key(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let (team, sha256) = (text(&body, "name").to_string(), text(&body, "sha256"));
            let entries = entries(&console);
            let entry = entries
                .iter()
                .find(|e| e.sha256 == sha256 && admin.covers_entry(e))
                .ok_or_else(|| {
                    Fail(
                        StatusCode::NOT_FOUND,
                        "There is no such key in the keys file: someone revoked it, or it was rotated. Reload the page.".into(),
                    )
                })?;
            if !edit::edits_key(&admin, entry)
                || admin.read_only
                || !admin.covers(&entry.org, &team, entry.customer.as_deref())
                || (entry.admin && !edit::full_admin(&admin))
            {
                return Err(refuse(&console, &admin, "move_key").await);
            }
            if service(entry) {
                return Err(bad(format!(
                    "{} holds a service key, which belongs to an app, not a person: groups hold people. Manage the app's key on the Apps page.",
                    entry.name
                )));
            }
            if !exists(&console, &entries, &team)? {
                return Err(bad(format!(
                    "There is no group {team}. Pick one from the list, or create it first on the Groups page."
                )));
            }
            if entry.team == team {
                return Ok(ok(
                    json!({ "message": format!("{} is in group {team} already.", entry.name) }),
                ));
            }
            stopped(&console, &entry.team)?;
            move_keys(&console, &admin, &[entry], &entry.team, &team).await?;
            Ok(ok(json!({
                "message": format!("{} is in group {team} now. Every gateway uses it within 2 seconds.", entry.name),
            })))
        }
        .await,
    )
}

/// Renames a group: every place the policy names it changes with it, then every key in it moves in one step. A
/// rename whose policy change would wait for a second admin's approval is refused before anything changes.
async fn rename(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !manages(&admin) {
                return Err(refuse(&console, &admin, "rename_team").await);
            }
            let body = body_of(&bytes)?;
            let (name, to) = (text(&body, "name").to_string(), text(&body, "to").to_string());
            name_ok(&to, "group", "design").map_err(bad)?;
            let entries = entries(&console);
            if !exists(&console, &entries, &name)? {
                return Err(bad(format!(
                    "There is no group {name}: someone renamed or deleted it. Reload the page."
                )));
            }
            if name == to {
                return Ok(ok(json!({ "message": format!("Group {name} has that name already.") })));
            }
            if exists(&console, &entries, &to)? {
                return Err(bad(format!(
                    "There is a group named {to} already. Pick another name. To put the two together, move the people of {name} into {to}, then delete {name}."
                )));
            }
            stopped(&console, &name)?;
            let keys: Vec<&KeyEntry> = entries.iter().filter(|e| e.team == name).collect();
            let (text, base) = current(&console)?;
            let mut tree = versions::tree(&text).map_err(|e| bad(sentence(&e)))?;
            let named = !rename_in(&mut tree, &name, None).is_empty() || listed(&tree, &name);
            // A policy change held for a second admin would leave the keys under the new name and the rules under the
            // old one until it is approved: refused before anything changes.
            let c = console.config();
            if !keys.is_empty()
                && named
                && base.is_some()
                && config::load(&c.policy, Some(&c.keys)).is_ok_and(|live| versions::approval_needed(&live))
            {
                return Err(bad(format!(
                    "A policy change here waits for a second admin's approval, so group {name} cannot be renamed in one step: its people would move before the rules that name it. Rename {name} to {to} in the policy and have it approved, then move the people of {name} into {to} on this page."
                )));
            }
            let note = format!("Rename group {name} to {to}");
            // The note is how the audit log tells the change in words.
            let target = json!({
                "team": name, "to": to, "note": note,
                "keys": keys.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            });
            if named {
                let saved = commit(&console, &admin, "rename_team", note, target, |tree| {
                    rename_in(tree, &name, Some(&to));
                    if let Some(Value::Array(teams)) = tree.get_mut("teams") {
                        for t in teams.iter_mut().filter_map(Value::as_object_mut) {
                            if t.get("name").and_then(Value::as_str) == Some(name.as_str()) {
                                t.insert("name".into(), to.clone().into());
                            }
                        }
                    }
                    Ok(())
                })
                .await?;
                if edit::previewing() {
                    return Ok(saved);
                }
            } else {
                let act = Act {
                    action: "rename_team",
                    by: Some((&admin.name, &admin.team)),
                    key: None,
                    target,
                };
                if record(&console, &act, None, None).await.is_err() {
                    return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
                }
            }
            if !keys.is_empty()
                && let Err(Fail(_, why)) = move_keys(&console, &admin, &keys, &name, &to).await
            {
                let done = if named { format!("Group {name} is renamed to {to} in the policy, but its keys did not move: ") } else { String::new() };
                return Err(bad(format!(
                    "{done}{why} Move the people of {name} into {to} on the Groups page."
                )));
            }
            Ok(ok(json!({
                "message": format!("Group {name} is now {to}. Every gateway uses it within 2 seconds."),
            })))
        }
        .await,
    )
}

/// Deletes an empty group the policy names nowhere but in its `teams:` list.
async fn remove(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !manages(&admin) {
                return Err(refuse(&console, &admin, "remove_team").await);
            }
            let body = body_of(&bytes)?;
            let name = text(&body, "name").to_string();
            let held = entries(&console).iter().filter(|e| e.team == name).count();
            if held > 0 {
                return Err(bad(format!(
                    "Group {name} still has {}: move them to another group first, then delete it.",
                    enterplace_core::count(held, "key")
                )));
            }
            let (text, _) = current(&console)?;
            let mut tree = versions::tree(&text).map_err(|e| bad(sentence(&e)))?;
            let named = rename_in(&mut tree, &name, None);
            if !named.is_empty() {
                return Err(bad(format!(
                    "The policy still names group {name} under {}: change or remove those entries first, then delete the group.",
                    named.join(", ")
                )));
            }
            let note = format!("Delete group {name}");
            commit(&console, &admin, "remove_team", note, json!({ "team": name }), |tree| {
                remove_named(tree, "teams", &name, "group")
            })
            .await
        }
        .await,
    )
}
