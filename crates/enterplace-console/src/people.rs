//! People and workloads in the console app (`/console/app/#/people`): every key by name and team, its status (active,
//! expiring, expired, over its own budget, stopped by a kill switch), what it spent, and its requests; issue a key or
//! a person token, change what a key may do, rotate it, revoke it.
//!
//! The keys file only ever changes through `keyfile`, recorded in the audit chain first with who made the change,
//! and every gateway reads it again within 2 seconds. A new key is in the answer once and in no record or file.

use std::collections::HashMap;

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
    keyfile,
    kill::Kill,
    policy::{Budget, Period, Permission, Principal},
};
use serde_json::{Map, Value, json};

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED,
    api::{Fail, answer, bad, body_of, ok, sentence, signed_in, text},
    edit, figures, issued_as, keys_for, pages, read_only, record, records_for, redirect, revoked,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page and its key editor moved to the app: old links land on the same view there.
        .route("/people", get(|uri: Uri| async move { moved(&uri, "") }))
        .route(
            "/people/edit",
            get(|uri: Uri| async move { moved(&uri, "edit") }),
        )
        .route("/api/people", get(list))
        .route("/api/people/issue", post(issue))
        .route("/api/people/import", post(import))
        .route("/api/people/revoke", post(revoke))
        .route("/api/people/edit", post(edit_key))
        .route("/api/people/rotate", post(rotate))
}

/// The app's People route for an old address, keeping what its query asked for (a dialog, a search, a toast).
fn moved(uri: &Uri, edit: &str) -> Response {
    let query = Form::of(uri);
    let mut kept: Vec<String> = Vec::new();
    for name in [
        "issue", "name", "team", "revoke", "q", "revoked", "hash", "page",
    ] {
        let v = query.get(name);
        if !v.is_empty() {
            kept.push(format!("{name}={}", crate::html::enc(v)));
        }
    }
    if edit == "edit" && !query.get("sha256").is_empty() {
        kept.push(format!("edit={}", crate::html::enc(query.get("sha256"))));
    }
    let mut to = "/console/app/#/people".to_string();
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

/// What one key spent this month and today, and whether its own budget refused it then.
#[derive(Default)]
struct KeySpend {
    day: f64,
    month: f64,
    refused_day: bool,
    refused_month: bool,
}

/// A key's status, its own limits, its budget meter and the way out of a refusal, as the table shows them.
fn status(
    entry: &KeyEntry,
    by_key: &HashMap<String, KeySpend>,
    now: &str,
    soon: &str,
    read_only: bool,
    stopped: Option<&Kill>,
    may_restore: bool,
) -> Value {
    let key = &entry.sha256[..8];
    let expired = Principal {
        expires: entry.expires.clone(),
        ..Principal::default()
    }
    .expired(now);
    let meter = entry.budget.map(|b| {
        let per_day = b.per == Period::Day;
        let (spent, refused) = by_key.get(key).map_or((0.0, false), |k| {
            if per_day {
                (k.day, k.refused_day)
            } else {
                (k.month, k.refused_month)
            }
        });
        let over = refused || spent >= b.usd;
        let pct = (spent / b.usd * 100.0).round().clamp(0.0, 100.0);
        json!({
            "text": format!("{} of {} {}", figures::money(spent), figures::money(b.usd), if per_day { "today" } else { "this month" }),
            "percent": pct,
            "over": over,
        })
    });
    let spent = meter.as_ref().is_some_and(|m| m["over"] == true);
    let expires = entry.expires.as_deref().unwrap_or("");
    // The date alone, as the keys file writes most expiries: a enterplace login key carries a time too.
    let expires = expires.get(..10).unwrap_or(expires);
    let (tag, kind, note) = if let Some(k) = stopped {
        (
            "Stopped".to_string(),
            "refused",
            format!("{}: {}", k.label(), k.reason),
        )
    } else if expired {
        ("Expired".to_string(), "refused", format!("on {expires}"))
    } else if spent && !expires.is_empty() {
        (
            "Budget reached".to_string(),
            "refused",
            format!("expires {expires}"),
        )
    } else if spent {
        ("Budget reached".to_string(), "refused", String::new())
    } else if !expires.is_empty() && expires <= soon {
        (
            format!("Expires {}", pages::day_words(expires, true)),
            "",
            String::new(),
        )
    } else if !expires.is_empty() {
        ("Active".to_string(), "allow", format!("expires {expires}"))
    } else {
        ("Active".to_string(), "allow", String::new())
    };
    let mut notes: Vec<String> = Vec::new();
    if !note.is_empty() {
        notes.push(note);
    }
    // The key's own limits, within its rule's.
    if let Some(models) = &entry.models {
        notes.push(format!("models {}", models.join(", ")));
    }
    if let Some(tpm) = entry.tpm {
        notes.push(format!(
            "{} tokens a minute",
            crate::html::thousands(tpm as usize)
        ));
    }
    let fix = if let Some(k) = stopped {
        if may_restore {
            json!({ "kind": "restore", "scope": k.scope, "value": k.value })
        } else {
            json!({ "kind": "command", "text": pages::unkill_command(k) })
        }
    } else if expired && !read_only {
        json!({ "kind": "reissue", "name": entry.name, "team": entry.team })
    } else if spent {
        json!({ "kind": "refusals", "href": format!("/console/audit?verdict=refused&q={key}") })
    } else {
        Value::Null
    };
    json!({ "tag": tag, "kind": kind, "notes": notes, "meter": meter, "fix": fix })
}

async fn list(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            if !admin.may(Permission::SeeKeys) {
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Your role, {}, does not have the {} permission this page needs. Ask an Enterplace admin to add it to the role under roles: in the policy.",
                        admin.role,
                        Permission::SeeKeys.word()
                    ),
                ));
            }
            let config = console.config();
            let keys_file = config.keys.file_name().map_or_else(
                || config.keys.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let may = json!({
                "issue": !admin.read_only && admin.may(Permission::IssueKeys),
                "revoke": !admin.read_only && admin.may(Permission::RevokeKeys),
                "restore": admin.may(Permission::Kill),
                "full_admin": edit::full_admin(&admin),
            });
            let base = json!({
                "keys_file": keys_file,
                "keys_path": config.keys.display().to_string(),
                "read_only": admin.read_only,
                "may": may,
                "stop_agent": crate::start::kill_prompt(&crate::base(), None),
                "bring": bring(&config.policy, &config.keys),
                "start_command": format!("enterplace key new sarah.miller --team platform --url {}", crate::base()),
                "docs": format!("{}/governance/keys/", crate::start::DOCS),
                // What fills an empty page, as Start here words it for every page.
                "empty": crate::start::empty_for("People and workloads", &crate::base()).map(|e| json!({
                    "title": e.title,
                    "body": e.body,
                    "action": { "label": e.action.0, "href": e.action.1 },
                    "docs": format!("{}{}", crate::start::DOCS, e.docs),
                })),
            });
            let mut out = base.as_object().cloned().unwrap_or_default();
            let entries = match keys_for(&admin, &config.keys, config::read_keys(&config.keys)) {
                Ok(Some(text)) => match config::key_entries(&config.keys, &text) {
                    Ok(entries) => entries,
                    Err(problems) => {
                        out.insert(
                            "error".into(),
                            format!(
                                "{} Fix the file and open this page again. Keys cannot be issued or revoked here until it loads.",
                                problems.join(" ")
                            )
                            .into(),
                        );
                        return Ok(ok(Value::Object(out)));
                    }
                },
                Ok(None) => Vec::new(),
                Err(err) => {
                    out.insert("error".into(), err.into());
                    return Ok(ok(Value::Object(out)));
                }
            };
            let mut teams: Vec<&str> = entries.iter().map(|e| e.team.as_str()).collect();
            teams.sort_unstable();
            teams.dedup();
            let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            out.insert(
                "lead".into(),
                format!(
                    "{} for {} in {}. A key is shown once: Enterplace keeps only its hash.",
                    enterplace_core::count(entries.len(), "key"),
                    if names.len() == 1 {
                        "1 person or app".to_string()
                    } else {
                        format!("{} people and apps", names.len())
                    },
                    enterplace_core::count(teams.len(), "team"),
                )
                .into(),
            );
            out.insert("entries".into(), entries_json(&console, &admin, &entries));
            Ok(ok(Value::Object(out)))
        }
        .await,
    )
}

/// How 200 people get keys without an admin issuing each: single sign-on with `enterplace login`, SCIM, or a list.
/// What the policy has set decides which the panel says is on.
fn bring(policy: &std::path::Path, keys: &std::path::Path) -> Value {
    let loaded = config::load(policy, Some(keys)).ok();
    let sso = loaded
        .as_ref()
        .is_some_and(|l| l.sso.is_some() || l.saml.is_some());
    let login = loaded.as_ref().is_some_and(|l| {
        l.sso.as_ref().is_some_and(|s| s.self_issue.is_some())
            || l.saml.as_ref().is_some_and(|s| s.self_issue.is_some())
    });
    let base = crate::base();
    let state = match (sso, login) {
        (true, true) => format!(
            "On: developers run enterplace login {base} and get their own key, named by their email, in the team their groups map to."
        ),
        (true, false) => "Single sign-on is on for the console, and enterplace login is off: let people get their own keys with it so developers do not wait for an admin.".to_string(),
        _ => "Not set up: the policy has no single sign-on, so each key is issued by an admin.".to_string(),
    };
    json!({
        "on": sso && login,
        "state": state,
        "agent": crate::start::sign_on_prompt(
            &base,
            &policy.display().to_string(),
            enterplace_core::store::policy_store(policy).is_some(),
        ),
        "docs": format!("{}/governance/single-sign-on/", crate::start::DOCS),
        "scim_docs": format!("{}/operations/scim/", crate::start::DOCS),
        "import_agent": crate::start::import_prompt(&base, &keys.display().to_string()),
    })
}

fn entries_json(console: &Console, admin: &Admin, entries: &[KeyEntry]) -> Value {
    let config = console.config();
    let log = records_for(admin, &config.audit).ok().flatten();
    let kills = enterplace_core::kill::read(&enterplace_core::kill::path_beside(&config.keys))
        .unwrap_or_default();
    // Requests and the last one, per key (a person may hold an admin key and a person token under one name), from
    // the audit log. Records are in time order, so the last seen is the latest.
    let mut seen: HashMap<String, (usize, String)> = HashMap::new();
    // Person tokens made before their kind went into the keys file: their issue record says so.
    let mut tokens: std::collections::HashSet<String> = std::collections::HashSet::new();
    let today = pages::today();
    let mut by_key: HashMap<String, KeySpend> = HashMap::new();
    let s = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    for line in log.as_deref().unwrap_or("").lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let time = s(&record, "time");
        let (day, month) = (time.starts_with(&today), time.get(..7) == today.get(..7));
        let key = s(&record, "key");
        if !key.is_empty() && month {
            let k = by_key.entry(key).or_default();
            let usd = record
                .get("charged_usd")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let refused = s(&record, "code") == "key_budget_exceeded";
            k.month += usd;
            k.refused_month |= refused;
            if day {
                k.day += usd;
                k.refused_day |= refused;
            }
        }
        if s(&record, "action") == "issue_key" && record["target"]["person_token"] == true {
            tokens.insert(s(&record["target"], "sha256_prefix"));
        }
        // Requests only: an admin's sign-ins and key changes are not requests through the gateway.
        if s(&record, "verdict").is_empty() || record.get("event").is_some() {
            continue;
        }
        let item = seen.entry(s(&record, "key")).or_default();
        item.0 += 1;
        item.1 = time;
    }
    let now = enterplace_core::audit::timestamp();
    let soon = pages::date_in(14);
    let may_restore = admin.may(Permission::Kill);
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                let hash = &entry.sha256[..8];
                let (count, last) = seen.get(hash).cloned().unwrap_or_default();
                let kind = match entry.options.metadata.get("kind").map(String::as_str) {
                    _ if entry.admin => "admin key",
                    Some(crate::PERSON_TOKEN_KIND) => "person token",
                    _ if tokens.contains(hash) => "person token",
                    Some("workload") => "workload key",
                    _ => "key",
                };
                // A model switch stops one model, not the person: only the switches that stop every request of this key.
                let stopped = kills.iter().find(|k| {
                    k.scope != "model" && k.stops(&entry.name, &entry.team, &entry.sha256, None)
                });
                let (budget, per) = entry
                    .budget
                    .map_or((String::new(), "month".to_string()), |b| (b.usd.to_string(), b.per.word()));
                json!({
                    "name": entry.name,
                    "team": entry.team,
                    "admin": entry.admin,
                    "kind": kind,
                    "role": entry.role,
                    "sha256": entry.sha256,
                    "hash": hash,
                    "requests": count,
                    "last": if last.is_empty() { "never".to_string() } else { figures::time_list(&last) },
                    "status": status(entry, &by_key, &now, &soon, admin.read_only, stopped, may_restore),
                    "editable": edit::edits_key(admin, entry),
                    "fields": {
                        "expires": entry.expires.clone().unwrap_or_default(),
                        "budget": budget,
                        "per": per,
                        "models": entry.models.clone().unwrap_or_default().join(", "),
                        "tpm": entry.tpm.map(|t| t.to_string()).unwrap_or_default(),
                        "replaced_by": entry.options.replaced_by,
                    },
                })
            })
            .collect(),
    )
}

fn field<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    text(body, name)
}

fn flag(body: &Map<String, Value>, name: &str) -> bool {
    matches!(body.get(name), Some(Value::Bool(true)))
        || matches!(body.get(name), Some(Value::String(s)) if s == "1" || s == "true")
}

/// Issues a key, or a person token: the key is in this answer once, with the lines for each tool.
async fn issue(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !admin.may(Permission::IssueKeys) || admin.read_only {
                read_only(&console, &admin, "issue_key").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: you can see the keys, not issue them. Ask an admin, or ask to be added to an admin group at the identity provider.".into(),
                ));
            }
            let body = body_of(&bytes)?;
            let (name, team) = (field(&body, "name").to_string(), field(&body, "team").to_string());
            let (expires, budget, per) = (field(&body, "expires"), field(&body, "budget"), field(&body, "per"));
            let attributes = keyfile::Attributes {
                admin: flag(&body, "admin"),
                expires: (!expires.is_empty()).then(|| expires.to_string()),
                // Text that is not a number becomes NaN, which the keys file refuses with the budget's own message.
                budget: (!budget.is_empty()).then(|| Budget {
                    usd: budget.parse().unwrap_or(f64::NAN),
                    per: if per == "day" { Period::Day } else { Period::Month },
                }),
                // A person kept to one organization issues keys in it, and one kept to one customer keys for it.
                org: admin.org.clone().unwrap_or_default(),
                customer: match admin.customers.as_slice() {
                    [one] => Some(one.clone()),
                    _ => None,
                },
                ..keyfile::Attributes::default()
            };
            if !admin.covers(&attributes.org, &team, attributes.customer.as_deref()) {
                read_only(&console, &admin, "issue_key").await;
                return Err(bad(format!(
                    "Your role keeps you to team{} {}{}: issue the key in one of them.",
                    if admin.teams.len() == 1 { "" } else { "s" },
                    admin.teams.join(", "),
                    if admin.customers.len() > 1 {
                        format!(" and customers {}, and your role cannot pick one here", admin.customers.join(", "))
                    } else {
                        String::new()
                    }
                )));
            }
            // An admin key gives every right: only someone who holds them all may make one.
            if attributes.admin && !edit::full_admin(&admin) {
                read_only(&console, &admin, "issue_key").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "Only an admin of the whole install may issue an admin key.".into(),
                ));
            }
            let person_token = flag(&body, "person_token");
            let mut attributes = attributes;
            // A service key names an app or an agent, not a person: the app's Apps and agents page lists it by this.
            if flag(&body, "workload") && !person_token {
                attributes.options.metadata.insert("kind".into(), "workload".into());
            }
            let (key, rotated) = issued_as(&console, &admin, &name, &team, attributes, person_token)
                .await
                .map_err(bad)?;
            let lines = pages::tool_lines(&crate::base(), &key);
            Ok(ok(json!({
                "key": key,
                "name": name,
                "team": team,
                "rotated": rotated,
                "person_token": person_token,
                "keys_path": console.config().keys.display().to_string(),
                "lines": lines,
            })))
        }
        .await,
    )
}

/// Imports a list of people (`name,team[,budget[,kind]]` per line, pasted or from a CSV file): every line is
/// checked first, and while one is wrong nothing is issued and each wrong line comes back with what to fix. Then
/// each key or person token is issued, recorded once as `import_keys` with the count, and the keys are in this
/// answer once, with a CSV of name, team and key.
async fn import(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !admin.may(Permission::IssueKeys) || admin.read_only {
                read_only(&console, &admin, "import_keys").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: you can see the keys, not issue them. Ask an admin.".into(),
                ));
            }
            let body = body_of(&bytes)?;
            let keys = console.config().keys.clone();
            let text = enterplace_core::store::attached(&keys)
                .map(|s| s.keys_text())
                .or_else(|| config::read_keys(&keys).ok().flatten())
                .unwrap_or_default();
            let taken: Vec<String> = config::key_entries(&keys, &text)
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.name)
                .collect();
            let wrong = |errors: Vec<(usize, String)>| {
                let rows: Vec<Value> = errors
                    .iter()
                    .map(|(line, why)| json!({ "line": line, "error": format!("{why}.") }))
                    .collect();
                ok(json!({
                    "message": format!("Nothing was issued: {} to fix.", enterplace_core::count(rows.len(), "line")),
                    "errors": rows,
                }))
            };
            let rows = match keyfile::import_rows(field(&body, "text"), &taken) {
                Ok(rows) => rows,
                Err(errors) => return Ok(wrong(errors)),
            };
            let org = admin.org.clone().unwrap_or_default();
            let customer = match admin.customers.as_slice() {
                [one] => Some(one.clone()),
                _ => None,
            };
            let mut planned = Vec::new();
            let mut errors = Vec::new();
            for row in rows {
                if !admin.covers(&org, &row.team, customer.as_deref()) {
                    errors.push((row.line, format!("Your role keeps you to team{} {}: issue keys in one of them", if admin.teams.len() == 1 { "" } else { "s" }, admin.teams.join(", "))));
                    continue;
                }
                let mut attributes = keyfile::row_attributes(&row, &org);
                attributes.customer.clone_from(&customer);
                // What the person's role may grant (`key_bounds:`), as for one key.
                if let Err(why) = crate::bound(&console, Some(&admin.role), &mut attributes).await {
                    errors.push((row.line, why));
                    continue;
                }
                planned.push((row, attributes));
            }
            if !errors.is_empty() {
                return Ok(wrong(errors));
            }
            let act = Act {
                action: "import_keys",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({
                    "count": planned.len(),
                    "people": planned.iter().map(|(r, _)| json!({ "name": r.name, "team": r.team, "person_token": r.person_token })).collect::<Vec<_>>(),
                }),
            };
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            let made = tokio::task::spawn_blocking(move || {
                let mut issued = Vec::new();
                for (row, attributes) in &planned {
                    match keyfile::issue_row(row, attributes, &keys) {
                        Ok(key) => issued.push((row.name.clone(), row.team.clone(), key)),
                        Err(why) => return (issued, Some(format!("line {}: {why}", row.line))),
                    }
                }
                (issued, None)
            })
            .await
            .unwrap_or_else(|err| (Vec::new(), Some(format!("the import stopped: {err}"))));
            let (issued, failed) = made;
            if let Some(why) = &failed {
                let _ = record(&console, &act, Some("keys_file"), Some(why)).await;
            }
            let shown: Vec<Value> = issued
                .iter()
                .map(|(name, team, key)| json!({ "name": name, "team": team, "key": key }))
                .collect();
            Ok(ok(json!({
                "message": match &failed {
                    None => format!("Issued {}. Each is shown once: copy them or download the CSV now.", enterplace_core::count(issued.len(), "key")),
                    Some(why) => format!("Issued {} before one failed ({why}). They are shown once below; fix the cause and import the rest.", enterplace_core::count(issued.len(), "key")),
                },
                "issued": shown,
                "lines": issued.iter().map(|(name, team, key)| format!("{name},{team},{key}")).collect::<Vec<_>>().join("\n"),
                "csv": keyfile::import_csv(&issued),
            })))
        }
        .await,
    )
}

/// The entry a change names by its hash, when the person may see it.
fn entry_for(console: &Console, admin: &Admin, sha256: &str) -> Result<KeyEntry, Fail> {
    edit::entry_of(console, sha256)
        .filter(|e| admin.covers_entry(e))
        .ok_or_else(|| {
            Fail(
                StatusCode::NOT_FOUND,
                "There is no such key in the keys file: someone revoked it, or it was rotated. Reload the page.".into(),
            )
        })
}

async fn revoke(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let entry = entry_for(&console, &admin, field(&body, "sha256"))?;
            if !admin.may(Permission::RevokeKeys) || admin.read_only {
                read_only(&console, &admin, "revoke_key").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: you can see the keys, not revoke them. Ask an admin.".into(),
                ));
            }
            if field(&body, "confirm") != entry.name {
                return Err(bad(format!("Type {} exactly, to confirm which key goes.", entry.name)));
            }
            revoked(&console, &admin, &entry).await.map_err(bad)?;
            Ok(ok(json!({
                "message": format!(
                    "The key of {}, key hash {}, is revoked. Requests with it are refused within 2 seconds.",
                    entry.name,
                    &entry.sha256[..8]
                ),
            })))
        }
        .await,
    )
}

/// Changes what a key may do: admin, expiry, its own budget, models and tokens per minute. The key itself stays.
async fn edit_key(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let entry = entry_for(&console, &admin, field(&body, "sha256"))?;
            if !edit::edits_key(&admin, &entry) || admin.read_only {
                read_only(&console, &admin, "edit_key").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: ask an admin to change keys.".into(),
                ));
            }
            let value = |name: &str| Some(field(&body, name).to_string()).filter(|v| !v.is_empty());
            let attributes = keyfile::Attributes {
                admin: flag(&body, "admin"),
                expires: value("expires"),
                // Text that is not a number becomes NaN, which the edit refuses with the budget's own message.
                budget: value("budget").map(|b| Budget {
                    usd: b.parse().unwrap_or(f64::NAN),
                    per: Period::from_word(field(&body, "per")).unwrap_or(Period::Month),
                }),
                models: value("models").map(|m| {
                    m.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
                tpm: match value("tpm").map(|t| t.parse::<u32>()) {
                    None => None,
                    Some(Ok(t)) => Some(t),
                    Some(Err(_)) => Some(0),
                },
                ..keyfile::Attributes::default()
            };
            // An admin key gives every right: only someone who holds them all may make one or change one.
            if (entry.admin || attributes.admin) && !edit::full_admin(&admin) {
                read_only(&console, &admin, "edit_key").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "Only an admin of the whole install may change an admin key or make a key an admin.".into(),
                ));
            }
            let act = Act {
                action: "edit_key",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({
                    "name": entry.name, "team": entry.team, "sha256_prefix": &entry.sha256[..8],
                    "admin": attributes.admin, "expires": attributes.expires,
                    "budget": attributes.budget.map(|b| json!({ "usd": b.usd, "per": b.per.word() })),
                    "models": attributes.models, "tpm": attributes.tpm,
                }),
            };
            // The last admin key keeps its admin: nobody could sign in again.
            if entry.admin && !attributes.admin {
                let keys = &console.config().keys;
                let admins = enterplace_core::store::attached(keys)
                    .map(|s| s.keys_text())
                    .or_else(|| config::read_keys(keys).ok().flatten())
                    .and_then(|t| config::key_entries(keys, &t).ok())
                    .map_or(0, |e| e.iter().filter(|e| e.admin).count());
                if admins <= 1 {
                    let _ = record(&console, &act, Some("last_admin"), None).await;
                    return Err(bad(
                        "This is the only admin key. Make another key an admin first, so someone can still sign in.",
                    ));
                }
            }
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            let (keys, sha256) = (console.config().keys.clone(), entry.sha256.clone());
            let done = tokio::task::spawn_blocking(move || keyfile::edit(&keys, &sha256, &attributes))
                .await
                .unwrap_or_else(|err| Err(format!("nothing was changed: {err}. Try again.")));
            let error = match done {
                Ok(Some(_)) => {
                    return Ok(ok(json!({
                        "message": format!("The key of {} is changed. Every gateway uses it within 2 seconds.", entry.name),
                    })));
                }
                Ok(None) => "The key is no longer there: someone revoked it. Nothing was changed.".to_string(),
                Err(err) => sentence(&err),
            };
            let _ = record(&console, &act, Some("keys_file"), Some(&error)).await;
            Err(bad(error))
        }
        .await,
    )
}

/// Rotates a key: a new key with the same settings, in this answer once, and the old one ends after the grace. The
/// same change as `POST /admin/keys/<prefix>/rotate`, recorded before it is made.
async fn rotate(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let entry = entry_for(&console, &admin, field(&body, "sha256"))?;
            if !edit::edits_key(&admin, &entry) || admin.read_only {
                read_only(&console, &admin, "rotate_key").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: ask an admin to rotate keys.".into(),
                ));
            }
            let mut act = Act {
                action: "rotate_key",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({ "name": entry.name, "team": entry.team, "sha256_prefix": &entry.sha256[..8] }),
            };
            // The new key carries the old one's rights and its issuer sees it: only someone who holds them all may make it.
            if (entry.admin || entry.role.is_some()) && !edit::full_admin(&admin) {
                let _ = record(&console, &act, Some("not_permitted"), None).await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "Only an admin of the whole install may rotate an admin key or a key with a role.".into(),
                ));
            }
            if let Some(by) = &entry.options.replaced_by {
                let _ = record(&console, &act, Some("already_rotated"), None).await;
                return Err(bad(format!(
                    "This key was already rotated and replaced by key {by}. Rotate the new key instead, or revoke this one."
                )));
            }
            let grace = match field(&body, "grace") {
                "" => "24h",
                typed => typed,
            };
            let wait = match keyfile::grace(grace) {
                Ok(wait) => wait,
                Err(problem) => {
                    let _ = record(&console, &act, Some("invalid_request"), None).await;
                    return Err(bad(sentence(&problem)));
                }
            };
            let key = enterplace_core::id::new_key().map_err(|err| bad(sentence(&format!("{err}. Try again"))))?;
            let until = keyfile::rotation_end(&entry, wait);
            act.target = json!({
                "name": entry.name, "team": entry.team, "sha256_prefix": &entry.sha256[..8],
                "replaced_by": &enterplace_core::id::sha256_hex(key.as_bytes())[..8], "old_key_until": until,
            });
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            let (keys, old, new, end) = (console.config().keys.clone(), entry.clone(), key.clone(), until.clone());
            let done = tokio::task::spawn_blocking(move || keyfile::rotate(&keys, &old, &new, &end))
                .await
                .unwrap_or_else(|err| Err(format!("nothing was changed: {err}. Try again.")));
            match done {
                Ok(_) => Ok(ok(json!({
                    "key": key,
                    "name": entry.name,
                    "team": entry.team,
                    "until": until,
                    "message": format!(
                        "The old key keeps working until {until} (UTC), and every request made with it until then is recorded with key_rotated, so you can find who still uses it."
                    ),
                }))),
                Err(err) => {
                    let error = sentence(&err);
                    // The record above says it was allowed; this one says it did not happen.
                    let _ = record(&console, &act, Some("keys_file"), Some(&error)).await;
                    Err(bad(error))
                }
            }
        }
        .await,
    )
}
