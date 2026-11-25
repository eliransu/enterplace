//! The raw policy, its versions, the editor and the dry run in the console app (`/console/app/#/policy/raw`,
//! `#/policy/versions`, `#/policy/edit`): the policy in force with each problem `enterplace check` finds under its
//! line, its rules, providers and gateways; every saved version with its diff, approval, rejection and rollback; the
//! YAML editor, and a dry run of a draft against recent requests.
//!
//! A change is made only when the policy is kept in the store: each save is a new version through
//! `edit::save_version`, recorded in the audit chain first with who made it, checked as `enterplace check` checks a
//! file, and live on every gateway within 2 seconds, or waiting for a second admin when the live version sets
//! `store.approval: true`. A policy kept in a file has no editor here; its versions are the policies the gateway
//! loaded, read from the audit chain, and an earlier one is put back through the same checked save as a form edit.

use std::collections::HashMap;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use enterplace_core::{
    config, count,
    policy::{Models, Permission, Who},
    store::{self, PolicyVersion},
    versions::{self, DryRun, Refused, Replayed},
};
use serde_json::{Map, Value, json};

use crate::{
    Act, Console, Form, NOT_RECORDED,
    api::{Answer, Fail, answer, bad, body_of, ok, refused, sentence, signed_in, text},
    edit::{self, edits_policy},
    figures::{money, time_full, time_list},
    read_only, record, redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered pages moved to the app: old links land on the same line, version or draft there.
        .route(
            "/policy",
            get(|uri: Uri| async move { moved(&uri, "raw", &["line"]) }),
        )
        .route(
            "/policy/versions",
            get(|uri: Uri| async move { moved(&uri, "versions", &["version"]) }),
        )
        .route(
            "/policy/edit",
            get(|uri: Uri| async move { moved(&uri, "edit", &["add", "hours"]) }),
        )
        .route("/api/policy/raw", get(raw))
        .route("/api/policy/versions", get(list))
        .route("/api/policy/versions/{id}/{action}", post(decide))
        .route("/api/policy/editor", get(editor))
        .route("/api/policy/save", post(save))
        .route("/api/policy/dry-run", post(dry_run))
}

/// The app's route for an old address, keeping what its query asked for.
fn moved(uri: &Uri, page: &str, keep: &[&str]) -> Response {
    let query = Form::of(uri);
    let kept: Vec<String> = keep
        .iter()
        .filter(|name| !query.get(name).is_empty())
        .map(|name| format!("{name}={}", crate::html::enc(query.get(name))))
        .collect();
    let mut to = format!("/console/app/#/policy/{page}");
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

// ---------------------------------------------------------------- the raw policy

async fn raw(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let c = console.config();
            let path = &c.policy;
            let file = path.file_name().map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let text = match config::policy_text(path) {
                Ok(text) => text,
                Err(err) => {
                    return Ok(ok(json!({
                        "file": file,
                        "failed": { "title": "The policy file did not load", "body": err },
                    })));
                }
            };
            let loaded = config::load(path, Some(&c.keys));
            let live = edit::live(&console);
            let version = live.as_ref().map(|v| v.id);
            // Problems on a line of the policy file go under that line. Others are listed above it.
            let prefix = format!("{}:", path.display());
            let mut on_line: HashMap<usize, Vec<String>> = HashMap::new();
            let mut elsewhere = Vec::new();
            if let Err(problems) = &loaded {
                for problem in problems {
                    let placed = problem.strip_prefix(&prefix).and_then(|rest| {
                        let (n, msg) = rest.split_once(": ")?;
                        Some((n.parse::<usize>().ok()?, msg.to_string()))
                    });
                    match placed {
                        Some((n, msg)) => on_line.entry(n).or_default().push(msg),
                        None => elsewhere.push(problem.clone()),
                    }
                }
            }
            let lines: Vec<Value> = text
                .lines()
                .enumerate()
                .map(|(i, line)| {
                    let notes = on_line.remove(&(i + 1)).unwrap_or_default();
                    json!({ "n": i + 1, "text": line, "problems": notes })
                })
                .collect();
            let mut out = json!({
                "file": file,
                "path": path.display().to_string(),
                "version": version,
                "tag": version.map_or_else(|| "Read only".to_string(), |v| format!("Version {v}, live")),
                "lines": lines,
                "problems": elsewhere,
                "foot": match version {
                    Some(v) => format!("Live version {v} in the store, when this page was read."),
                    None => format!("Read from {} when this page was read.", path.display()),
                },
                "edit": live.is_some() && edits_policy(&admin),
                "store": live.is_some(),
                "banner": versions::file_differs(path).map(|v| format!(
                    "{} differs from live version {v}, and only its store: section is read: the store decides. Export the live version to update the file, or paste the file in the editor to make it a new version.",
                    path.display()
                )),
            });
            let Some(map) = out.as_object_mut() else {
                return Err(Fail(StatusCode::INTERNAL_SERVER_ERROR, "Try again.".into()));
            };
            match &loaded {
                Err(problems) => {
                    map.insert("lead".into(), json!(format!(
                        "enterplace check refuses this file: {}, each on its line below. A running gateway keeps the version it loaded.",
                        count(problems.len(), "problem")
                    )));
                }
                Ok(loaded) => {
                    let (rules, providers) = (
                        count(loaded.policy.rules(), "rule"),
                        count(loaded.providers.len(), "provider"),
                    );
                    map.insert("lead".into(), json!(match version {
                        Some(v) => format!("Version {v} in the store decides every request: {rules} and {providers}, read in order, the first that names the caller decides. Edit it here: each save is a new version, checked as enterplace check checks a file."),
                        None => format!("One file decides every request: {rules} and {providers}, read in order, the first that names the caller decides. Read only here: change the file and run enterplace check."),
                    }));
                    map.insert("rules".into(), rules_of(loaded));
                    map.insert(
                        "providers".into(),
                        loaded
                            .providers
                            .iter()
                            .map(|p| json!({
                                "name": p.name,
                                "meta": format!("{} at {}. Serves {}.", p.kind.word(), p.url, p.models.join(", ")),
                            }))
                            .collect(),
                    );
                    // The policy first start writes, one rule that lets everyone in: the page says what to add next.
                    let first_run = {
                        let rules = loaded.policy.rule_list();
                        rules.len() == 1
                            && rules[0].guardrails.is_empty()
                            && rules[0].limits.budgets.is_empty()
                            && loaded.policy.scope_limits().is_empty()
                            && loaded.policy_text.contains(r#"models: ["*"]"#)
                    };
                    if first_run {
                        let mut next = crate::start::empty_json("Policy", &crate::base());
                        // The button opens the budget step: it says so, and never reads as an editor on a read-only page.
                        if let Some(action) = next.get_mut("action") {
                            action["label"] = json!("Add a budget");
                        }
                        next["act"] = json!(admin.may(Permission::EditPolicy));
                        map.insert("next".into(), next);
                    }
                }
            }
            if let Some(store) = console
                .store()
                .filter(|_| admin.may(Permission::SeeRecords))
            {
                // A store that cannot be read leaves the panel out: the policy is still worth showing.
                let replicas = store.replicas().await.unwrap_or_default();
                map.insert(
                    "replicas".into(),
                    replicas
                        .iter()
                        .map(|r| json!({
                            "host": r.host,
                            "meta": format!("Version {}, schema {}. Started {}, last heartbeat {}.{}", r.version, r.schema, r.started, r.seen, r.policy_note()),
                            "healthy": r.healthy,
                        }))
                        .collect(),
                );
            }
            Ok(ok(out))
        }
        .await,
    )
}

/// Each rule, in order, with what it does in a sentence and the line it starts on.
fn rules_of(loaded: &config::Loaded) -> Value {
    loaded
        .policy
        .rule_list()
        .iter()
        .map(|r| {
            let who = match &r.who {
                Who::Team(team) => format!("Team {team}"),
                Who::Name(name) => name.clone(),
                Who::Tag(tag) => format!("Keys tagged {tag}"),
                Who::Any => "Everyone else".into(),
            };
            let models = match &r.models {
                Models::Any => "every model".to_string(),
                Models::Only(m) if m.is_empty() => "no model".to_string(),
                Models::Only(m) => m.join(", "),
            };
            let mut meta = format!("{who} may use {models}.");
            if !r.guardrails.is_empty() {
                let names: Vec<&str> = r.guardrails.iter().map(|g| g.name.as_str()).collect();
                meta.push_str(&format!(" Guardrails: {}.", names.join(", ")));
            }
            if let Some(b) = r.limits.budget() {
                meta.push_str(&format!(" Budget {} a {}.", money(b.usd), b.per.word()));
            }
            if let Some(rpm) = r.limits.rpm {
                meta.push_str(&format!(" {rpm} requests a minute each."));
            }
            json!({ "name": r.name, "meta": meta, "line": r.line })
        })
        .collect()
}

// ---------------------------------------------------------------- versions

const LEAD: &str = "Each save of the policy is a version. The live one decides every request; an earlier one can be put back in one click, as a new version.";

/// A version's state as its tag shows it: the word and the kind of tag.
fn state_tag(state: &str) -> Value {
    let (kind, word) = match state {
        store::LIVE => ("allow", "Live"),
        store::PENDING => ("warn", "Waiting for approval"),
        store::REJECTED => ("refused", "Rejected"),
        _ => ("", "Earlier"),
    };
    json!({ "kind": kind, "word": word, "detail": "" })
}

async fn list(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let store = match versions::store_for(&console.config().policy) {
                Ok(store) => store,
                Err(_) => return file_list(&console, &admin, &uri).await,
            };
            let all = store.policy_versions().unwrap_or_default();
            let selected: Option<i64> = Form::of(&uri).get("version").parse().ok();
            let editable = edits_policy(&admin);
            // What each gateway runs, from its heartbeat: a saved version no gateway runs never reads as in force.
            let replicas = store.replicas().await.unwrap_or_default();
            let spread = |v: &PolicyVersion| {
                let (n, m, refusals) = edit::spread(&replicas, v.id);
                let refusals: Vec<String> = refusals
                    .into_iter()
                    .map(|(host, why)| format!("Refused by {host}: {why}"))
                    .collect();
                let mut tag = state_tag(&v.state);
                if v.state == store::LIVE && m > 0 && n == 0 {
                    tag = json!({ "kind": "warn", "word": "Saved, in force nowhere", "detail": "" });
                }
                let shown = m > 0 && (v.state == store::LIVE || n > 0 || !refusals.is_empty());
                (tag, shown.then(|| format!("In force on {n} of {m} gateways")), refusals)
            };
            let rows: Vec<Value> = all
                .iter()
                .map(|v| {
                    let (tag, force, refusals) = spread(v);
                    json!({
                        "id": v.id,
                        "tag": tag,
                        "force": force,
                        "refusals": refusals,
                        "by": v.created_by,
                        "at": time_full(&v.created_at),
                        "note": v.note,
                        "decided": match (&v.decided_by, &v.decided_at) {
                            (Some(by), Some(at)) => format!("{} by {by}", time_full(at)),
                            _ => String::new(),
                        },
                    })
                })
                .collect();
            let detail = selected
                .and_then(|id| all.iter().find(|v| v.id == id))
                .map(|v| {
                    let base = versions::base_text(&store, v);
                    let diff: Vec<Value> = versions::diff(&base, &v.text)
                        .into_iter()
                        .map(|(n, text, kind)| json!({ "n": n, "text": text, "kind": kind }))
                        .collect();
                    let mut actions = Vec::new();
                    if editable {
                        if v.state == store::PENDING {
                            if v.created_by != admin.name {
                                actions.push("approve");
                            }
                            actions.push("reject");
                        } else if v.state != store::LIVE {
                            actions.push("rollback");
                        }
                        actions.push("dry_run");
                    }
                    let (tag, force, refusals) = spread(v);
                    json!({
                        "id": v.id,
                        "tag": tag,
                        "force": force,
                        "refusals": refusals,
                        "facts": [
                            ["Saved by", v.created_by],
                            ["Saved at", time_full(&v.created_at)],
                            ["Note", v.note],
                            ["SHA-256", v.sha256.get(..16).unwrap_or(&v.sha256)],
                        ],
                        "from": v.base.map_or_else(|| "nothing: the first version".to_string(), |b| format!("version {b}")),
                        "diff": diff,
                        "own": (v.state == store::PENDING && v.created_by == admin.name)
                            .then_some("You saved this version, so another admin approves it."),
                        "actions": actions,
                        "text": v.text,
                    })
                });
            Ok(ok(json!({
                "lead": LEAD,
                "edit": editable,
                "versions": rows,
                "detail": detail,
            })))
        }
        .await,
    )
}

/// What a saved version's toast says, by its state: a live one after the gateways reported on it.
async fn saved(console: &Console, v: &PolicyVersion) -> Response {
    let message = match v.state.as_str() {
        store::PENDING => format!(
            "Version {} is saved and waits for a second admin to approve it.",
            v.id
        ),
        store::REJECTED => format!(
            "Version {} is rejected. The live version stays in force.",
            v.id
        ),
        _ => edit::in_force(console, Some(v.id), &v.sha256).await,
    };
    ok(json!({ "message": message, "version": v.id, "state": v.state }))
}

async fn decide(
    State(console): State<Console>,
    Path((id, action)): Path<(i64, String)>,
    headers: HeaderMap,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let act_name: &'static str = match action.as_str() {
                "approve" => "approve_policy",
                "reject" => "reject_policy",
                "rollback" => "rollback_policy",
                _ => {
                    return Err(Fail(
                        StatusCode::NOT_FOUND,
                        format!(
                            "A version has no action \"{action}\". Use approve, reject or rollback."
                        ),
                    ));
                }
            };
            if !edits_policy(&admin) {
                read_only(&console, &admin, act_name).await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: ask an admin.".into(),
                ));
            }
            if act_name == "rollback_policy"
                && versions::store_for(&console.config().policy).is_err()
            {
                return put_back(&console, &admin, id).await;
            }
            let act = Act {
                action: act_name,
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({ "version": id }),
            };
            let v = edit::run(
                &console,
                &act,
                move |policy, keys, by| match act_name {
                    "rollback_policy" => versions::rollback(&policy, &keys, id, &by),
                    name => versions::decide(&policy, &keys, id, name == "approve_policy", &by),
                },
                &admin.name,
            )
            .await
            .map_err(|err| refused(&err))?;
            Ok(saved(&console, &v).await)
        }
        .await,
    )
}

// ---------------------------------------------------------------- versions of a policy kept in its file

const FILE_LEAD: &str = "The policy is kept in its file. Each policy the gateway loaded is a version here, read from the audit chain, which keeps every one whole. An earlier one can be put back in one click: the file is rewritten through the same checked save as any change.";

/// One policy the gateway loaded from its file, or refused, as the audit chain recorded it.
#[derive(Clone, Debug)]
struct FileVersion {
    id: i64,
    sha256: String,
    text: String,
    time: String,
    by: String,
    note: String,
    /// The reasons the gateway gave, for one it refused.
    refused: Option<String>,
}

/// The versions of a policy kept in its file, oldest first: each text the gateway loaded that differs from the one
/// before, and each one it refused. Who saved it and why come from the console's record of the save, made first.
// ponytail: reads the whole chain at each look, as the dry run does. An index of the config records when chains
// grow past what a page can read in a second.
fn file_versions(audit_path: &std::path::Path) -> Vec<FileVersion> {
    use std::io::BufRead as _;
    let Ok(reader) = enterplace_core::audit::chain_reader(audit_path) else {
        return Vec::new();
    };
    let mut saves: HashMap<String, (String, String, String)> = HashMap::new();
    let mut out: Vec<FileVersion> = Vec::new();
    let mut loaded = String::new();
    for line in reader.lines().map_while(Result::ok) {
        if !line.contains("\"policy\"") && !line.contains("\"config_rejected\"") {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Map<String, Value>>(&line) else {
            continue;
        };
        let field = |name: &str| record.get(name).and_then(Value::as_str).unwrap_or("");
        let time = field("time").to_string();
        match field("event") {
            "admin" => {
                let target = record.get("target").cloned().unwrap_or_default();
                let of = |name: &str| {
                    target
                        .get(name)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                if field("verdict") == "allow" && !of("policy").is_empty() {
                    saves.insert(
                        of("sha256"),
                        (field("person").to_string(), of("note"), of("policy")),
                    );
                }
            }
            "config_loaded" => {
                let sha = field("policy_sha256").to_string();
                if sha == loaded {
                    continue;
                }
                loaded.clone_from(&sha);
                let (by, note) = match saves.get(&sha) {
                    Some((by, note, _)) => (by.clone(), note.clone()),
                    None => (
                        String::new(),
                        format!("Loaded from the file ({})", field("trigger")),
                    ),
                };
                out.push(FileVersion {
                    id: out.len() as i64 + 1,
                    sha256: sha,
                    text: field("policy").to_string(),
                    time,
                    by,
                    note,
                    refused: None,
                });
            }
            "config_rejected" => {
                let sha = field("policy_sha256").to_string();
                if out.last().is_some_and(|v| v.sha256 == sha) {
                    continue;
                }
                let why: Vec<&str> = record
                    .get("problems")
                    .and_then(Value::as_array)
                    .map(|p| p.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let (by, note, text) = saves.get(&sha).cloned().unwrap_or_default();
                out.push(FileVersion {
                    id: out.len() as i64 + 1,
                    sha256: sha,
                    text,
                    time,
                    by,
                    note,
                    refused: Some(why.join(" ")),
                });
            }
            _ => {}
        }
    }
    out
}

/// The version of the file in force: the newest one loaded.
fn file_in_force(all: &[FileVersion]) -> Option<i64> {
    all.iter().rev().find(|v| v.refused.is_none()).map(|v| v.id)
}

fn file_tag(v: &FileVersion, live: Option<i64>) -> Value {
    match (&v.refused, live == Some(v.id)) {
        (Some(_), _) => json!({ "kind": "warn", "word": "Refused by the gateway", "detail": "" }),
        (None, true) => json!({ "kind": "allow", "word": "In force", "detail": "" }),
        (None, false) => json!({ "kind": "", "word": "Earlier", "detail": "" }),
    }
}

async fn file_list(console: &Console, admin: &crate::Admin, uri: &Uri) -> Answer {
    let audit = console.config().audit.clone();
    let all = tokio::task::spawn_blocking(move || file_versions(&audit))
        .await
        .unwrap_or_default();
    let live = file_in_force(&all);
    let editable = edits_policy(admin);
    let selected: Option<i64> = Form::of(uri).get("version").parse().ok();
    let rows: Vec<Value> = all
        .iter()
        .rev()
        .map(|v| {
            json!({
                "id": v.id,
                "tag": file_tag(v, live),
                "refusals": v.refused.iter().map(|why| format!("Refused by the gateway: {why}")).collect::<Vec<_>>(),
                "by": if v.by.is_empty() { "the file".to_string() } else { v.by.clone() },
                "at": time_full(&v.time),
                "note": v.note,
                "decided": "",
            })
        })
        .collect();
    let detail = selected
        .and_then(|id| all.iter().find(|v| v.id == id))
        .map(|v| {
            let before = all
                .iter()
                .rev()
                .find(|b| b.id < v.id && b.refused.is_none())
                .map(|b| b.text.clone())
                .unwrap_or_default();
            let diff: Vec<Value> = versions::diff(&before, &v.text)
                .into_iter()
                .map(|(n, text, kind)| json!({ "n": n, "text": text, "kind": kind }))
                .collect();
            let mut actions = Vec::new();
            if editable && live != Some(v.id) && !v.text.is_empty() {
                actions.push("rollback");
                actions.push("dry_run");
            }
            json!({
                "id": v.id,
                "tag": file_tag(v, live),
                "refusals": v.refused.iter().map(|why| format!("Refused by the gateway: {why}")).collect::<Vec<_>>(),
                "facts": [
                    ["Saved by", if v.by.is_empty() { "an edit of the file" } else { v.by.as_str() }],
                    ["Saved at", time_full(&v.time).as_str()],
                    ["Note", v.note.as_str()],
                    ["SHA-256", v.sha256.get(..16).unwrap_or(&v.sha256)],
                ],
                "from": if v.id == 1 { "nothing: the first version".to_string() } else { "the version before it".to_string() },
                "diff": diff,
                "own": Value::Null,
                "actions": actions,
                "text": v.text,
            })
        });
    Ok(ok(json!({
        "lead": FILE_LEAD,
        "file_mode": true,
        "edit": false,
        "versions": rows,
        "detail": detail,
    })))
}

/// Puts an earlier version of a policy kept in its file back: its text is written over the file through the same
/// checked save as any change, recorded as `rollback_policy`.
async fn put_back(console: &Console, admin: &crate::Admin, id: i64) -> Answer {
    let audit = console.config().audit.clone();
    let all = tokio::task::spawn_blocking(move || file_versions(&audit))
        .await
        .unwrap_or_default();
    let Some(v) = all.iter().find(|v| v.id == id && !v.text.is_empty()) else {
        return Err(Fail(
            StatusCode::NOT_FOUND,
            format!(
                "There is no version {id} of the policy file to put back. The Versions page lists them."
            ),
        ));
    };
    let (before, _) = crate::api::current(console)?;
    if before == v.text {
        return Ok(ok(
            json!({ "message": format!("Nothing changed: version {id} is the policy in the file.") }),
        ));
    }
    crate::api::save_text(
        console,
        admin,
        "rollback_policy",
        format!("Put back version {id}"),
        json!({ "version": id }),
        before,
        v.text.clone(),
        None,
    )
    .await
}

// ---------------------------------------------------------------- the editor and the dry run

async fn editor(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let Some(live) = edit::live(&console) else {
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    sentence(&versions::read_only_message(&console.config().policy)),
                ));
            };
            if !edits_policy(&admin) {
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "You are signed in read only: ask an admin to change the policy.".into(),
                ));
            }
            let query = Form::of(&uri);
            // A Start here step opens the editor with its lines already in: a draft, saved only as any edit is.
            let (text, note) = match crate::start::change(query.get("add")) {
                Some(change) => (
                    crate::start::apply(&live.text, &change).0,
                    "Added from a setup step",
                ),
                None => (live.text.clone(), ""),
            };
            let c = console.config();
            let approval = config::load(&c.policy, Some(&c.keys))
                .is_ok_and(|l| versions::approval_needed(&l));
            Ok(ok(json!({
                "lead": if approval {
                    "Edit the YAML, or load a file to import it. A save is checked as enterplace check checks a file, then waits for a second admin to approve it."
                } else {
                    "Edit the YAML, or load a file to import it. A save is checked as enterplace check checks a file; each gateway loads it within 2 seconds, and the save says on how many it is in force."
                },
                "text": text,
                "note": note,
                "base": live.id,
                "hours": hours_of(query.get("hours")),
                "save": if approval { "Save for approval" } else { "Save version" },
            })))
        }
        .await,
    )
}

/// The hours a dry run replays: 1 to 720, 24 when not given.
fn hours_of(text: &str) -> u64 {
    text.parse::<u64>().unwrap_or(24).clamp(1, 720)
}

/// The draft's text as sent. A browser sends a textarea's line breaks as CRLF.
fn draft(body: &Map<String, Value>) -> String {
    body.get("text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .replace("\r\n", "\n")
}

/// A number from a JSON number or a string.
fn number(body: &Map<String, Value>, name: &str) -> Option<i64> {
    body.get(name).and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
    })
}

async fn save(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(save_draft(&console, &headers, &bytes).await)
}

async fn save_draft(console: &Console, headers: &HeaderMap, bytes: &Bytes) -> Answer {
    let admin = signed_in(console, headers, true).await?;
    let body = body_of(bytes)?;
    if !edits_policy(&admin) {
        read_only(console, &admin, "propose_policy").await;
        return Err(Fail(
            StatusCode::FORBIDDEN,
            "You are signed in read only: ask an admin to change the policy.".into(),
        ));
    }
    // The version the editor read: a version saved since is refused rather than overwritten.
    let base = number(&body, "base");
    let note = text(&body, "note").to_string();
    let v = edit::save_version(console, &admin, "propose_policy", draft(&body), base, note)
        .await
        .map_err(|err| refused(&err))?;
    Ok(saved(console, &v).await)
}

async fn dry_run(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(replay(&console, &headers, &bytes).await)
}

async fn replay(console: &Console, headers: &HeaderMap, bytes: &Bytes) -> Answer {
    let admin = signed_in(console, headers, true).await?;
    let body = body_of(bytes)?;
    let text = draft(&body);
    let hours = match body.get("hours") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(24).clamp(1, 720),
        _ => hours_of(crate::api::text(&body, "hours")),
    };
    let act = Act {
        action: "dry_run_policy",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "hours": hours, "sha256": enterplace_core::id::sha256_hex(text.as_bytes()) }),
    };
    if record(console, &act, None, None).await.is_err() {
        return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
    }
    let c = console.config();
    let (policy, keys) = (c.policy.clone(), c.keys.clone());
    let stopped = |err: tokio::task::JoinError| {
        Refused::Store(format!("the dry run stopped: {err}. Try again."))
    };
    let checked = tokio::task::spawn_blocking(move || {
        let loaded = config::load(&policy, Some(&keys)).map_err(Refused::Invalid)?;
        let checked = versions::check(&policy, &keys, &text, &loaded).map_err(Refused::Invalid)?;
        Ok((loaded, checked))
    })
    .await
    .unwrap_or_else(|err| Err(stopped(err)));
    // With a store every gateway's requests are in its index; without, only this gateway's log has them.
    let run = match checked {
        Err(err) => Err(err),
        Ok((loaded, checked)) => {
            match enterplace_core::insights::attached(&loaded.audit_path).index {
                Some(index) => match versions::shared_lines(index.as_ref(), hours).await {
                    Err(err) => Err(Refused::Store(err)),
                    Ok(lines) => tokio::task::spawn_blocking(move || {
                        versions::dry_run_shared(
                            lines,
                            &loaded.audit_path,
                            hours,
                            &checked,
                            &loaded.policy,
                        )
                        .map_err(Refused::Store)
                    })
                    .await
                    .unwrap_or_else(|err| Err(stopped(err))),
                },
                None => tokio::task::spawn_blocking(move || {
                    versions::dry_run_log(&loaded.audit_path, hours, &checked, &loaded.policy)
                        .map_err(Refused::Store)
                })
                .await
                .unwrap_or_else(|err| Err(stopped(err))),
            }
        }
    };
    match run {
        Ok(run) => Ok(ok(report(&run))),
        Err(Refused::Invalid(problems)) => Err(bad(format!(
            "The draft would not pass enterplace check, so nothing was replayed. {}",
            problems.join(" ")
        ))),
        Err(err) => Err(refused(&err)),
    }
}

/// What the dry run found, ready to show: a summary, then each kind of change with its requests.
fn report(run: &DryRun) -> Value {
    let table = |title: &str, list: &[Replayed]| {
        let none = |rule: &str| {
            if rule.is_empty() {
                "none".to_string()
            } else {
                rule.to_string()
            }
        };
        json!({
            "title": title,
            "count": list.len(),
            // ponytail: the first 200 rows of each kind; the counts above them stay whole.
            "rows": list.iter().take(200).map(|r| json!({
                "time": time_list(&r.time),
                "person": r.person,
                "team": r.team,
                "model": r.model,
                "decision": format!("{} to {}", r.was, r.now),
                "rule": format!("{} to {}", none(&r.rule_was), none(&r.rule_now)),
            })).collect::<Vec<_>>(),
        })
    };
    let changed = run.now_refused.len() + run.now_allowed.len() + run.other_rule.len();
    json!({
        "message": if changed == 0 {
            "Dry run done: the draft decides every replayed request as the live policy did.".to_string()
        } else {
            format!("Dry run done: the draft decides {} differently.", count(changed, "request"))
        },
        "run": {
            "tag": if changed == 0 {
                json!({ "kind": "allow", "word": "No change", "detail": "" })
            } else {
                json!({ "kind": "warn", "word": "Changes", "detail": "" })
            },
            "summary": format!(
                "{} replayed since {}, {changed} changed. {} refused before the policy decided (a key, a budget, a guardrail, a kill switch) and not replayed.",
                count(run.replayed, "request"),
                time_full(&run.since),
                count(run.skipped, "request"),
            ),
            "note": run.note,
            "tables": [
                table("Now refused", &run.now_refused),
                table("Now allowed", &run.now_allowed),
                table("Allowed by another rule", &run.other_rule),
            ],
        },
    })
}
