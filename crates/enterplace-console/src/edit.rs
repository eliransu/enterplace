//! Editing the policy in the console: Teams, and the policy's versions (the editor, its diff, approval, a dry
//! run, rollback, export and import). A key's fields moved to the console app's People page (`people.rs`), prices to its Prices page (`prices.rs`).
//!
//! The policy changes only when it is kept in the store (`store.policy_from: store`): each save is a new version,
//! checked as `enterplace check` checks a file, recorded in the audit chain first, and live on every gateway within
//! 2 seconds, or waiting for a second admin when the live version sets `store.approval: true`. When the policy is
//! kept in the file, these pages show it and say how to change it there.
//!
//! No Claude Design design exists for these pages yet. They are built only from the console's existing components
//! (head, panel, table, tag, dialog, field, code, banner, toast) and its tokens, and need a design pass.

use std::fmt::Write as _;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use enterplace_core::{
    config,
    policy::{Permission, Who},
    store::{self, PolicyVersion},
    versions::{self, DryRun, Refused},
};
use serde_json::json;

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED,
    figures::{money, time_full, time_list},
    foreign,
    html::{Field, button, code, empty, esc, facts, field, head, link, motif, tag},
    page,
    pages::{self, PolicySource, alert, tool_page},
    read_only, record, redirect, same_origin,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        .route("/teams", get(teams_page))
        .route("/policy/versions", get(versions_page))
        .route("/policy/versions/{id}/{action}", post(version_action))
        .route("/policy/edit", get(editor_page))
        .route("/policy/save", post(save))
        .route("/policy/dry-run", post(dry_run))
        .route("/policy/export", get(export))
}

/// A message from the core, written as a sentence for a page.
fn sentence(text: &str) -> String {
    let mut text = text.trim().to_string();
    if let Some(first) = text.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    text
}

/// The live version, when the policy is kept in the store.
pub(crate) fn live(console: &Console) -> Option<PolicyVersion> {
    store::policy_store(&console.config().policy).and_then(|s| s.live_policy())
}

/// The version number a form says it started from.
fn base_of(form: &Form) -> Option<i64> {
    form.get("base").parse().ok()
}

/// What the policy page shows in its head and above the policy.
pub(crate) fn policy_source(console: &Console, admin: &Admin) -> PolicySource {
    let path = &console.config().policy;
    let live = live(console);
    let mut actions = link("Edit with forms", "", "/console/app/#/policy", false);
    if live.is_some() && edits_policy(admin) {
        actions.push_str(&link("Edit", "", "/console/policy/edit", false));
    }
    if live.is_some() {
        actions.push_str(&link(
            "Versions",
            "quiet",
            "/console/policy/versions",
            false,
        ));
    }
    // Kept in a file, the page already shows the file: exporting it again adds nothing.
    if live.is_some() {
        actions.push_str(&link(
            "Export YAML",
            "quiet",
            "/console/policy/export",
            false,
        ));
    }
    let banner = match versions::file_differs(path) {
        Some(v) => format!(
            r#"<div class="g-banner" role="status"><span class="t-body">{} differs from live version {v}, and only its store: section is read: the store decides. Export the live version to update the file, or paste the file in the editor to make it a new version.</span></div>"#,
            esc(&path.display().to_string())
        ),
        None => String::new(),
    };
    PolicySource {
        version: live.map(|v| v.id),
        actions,
        banner,
        replicas: Vec::new(),
    }
}

/// Records a change, then makes it as a new policy version. `Err` holds what to tell the person.
pub(crate) async fn save_version(
    console: &Console,
    admin: &Admin,
    action: &'static str,
    text: String,
    base: Option<i64>,
    note: String,
) -> Result<PolicyVersion, Refused> {
    let act = Act {
        action,
        by: Some((&admin.name, &admin.team)),
        key: None,
        // The policy holds no secrets: the chain keeps every draft whole, saved, pending or refused.
        target: json!({ "base": base, "note": note, "sha256": enterplace_core::id::sha256_hex(text.as_bytes()), "policy": text }),
    };
    run(
        console,
        &act,
        move |policy, keys, by| versions::propose(&policy, &keys, &text, base, &note, &by),
        &admin.name,
    )
    .await
}

/// Records `act`, runs `work` off the request threads, and records its failure if it fails.
async fn run(
    console: &Console,
    act: &Act<'_>,
    work: impl FnOnce(std::path::PathBuf, std::path::PathBuf, String) -> Result<PolicyVersion, Refused>
    + Send
    + 'static,
    by: &str,
) -> Result<PolicyVersion, Refused> {
    if record(console, act, None, None).await.is_err() {
        return Err(Refused::Store(NOT_RECORDED.into()));
    }
    let c = console.config();
    let (policy, keys, by) = (c.policy.clone(), c.keys.clone(), by.to_string());
    let done = tokio::task::spawn_blocking(move || work(policy, keys, by))
        .await
        .unwrap_or_else(|err| {
            Err(Refused::Store(format!(
                "nothing was changed: {err}. Try again."
            )))
        });
    if let Err(err) = &done {
        let code = match err {
            Refused::Invalid(_) => "invalid_policy",
            Refused::ReadOnly(_) => "policy_in_file",
            Refused::Forbidden(_) => "own_version",
            Refused::Conflict(_) => "version_conflict",
            Refused::Unknown(_) => "no_such_version",
            Refused::Store(_) => "store_unavailable",
        };
        let _ = record(console, act, Some(code), Some(&err.message())).await;
    }
    done
}

fn toast(text: &str) -> String {
    format!(
        r#"<div class="g-toasts"><div class="g-toast" role="status" tabindex="-1" data-focus><span class="g-toast__text t-body">{}</span></div></div>"#,
        esc(text)
    )
}

/// Where a saved version is shown, with a toast that says what happened.
fn saved(v: &PolicyVersion) -> Response {
    redirect(&format!(
        "/console/policy/versions?version={}&done={}",
        v.id, v.state
    ))
}

fn problems(err: &Refused) -> String {
    let lines: Vec<String> = match err {
        Refused::Invalid(problems) => problems.iter().map(|p| esc(p)).collect(),
        other => vec![esc(&sentence(&other.message()))],
    };
    alert(&lines.join("<br>"))
}

// ---------------------------------------------------------------- teams

async fn teams_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let query = Form::of(&uri);
    let title = "Teams";
    let here = "/console/teams";
    let lead = "Who is in each team.";
    let c = console.config();
    let loaded = match config::load(&c.policy, Some(&c.keys)) {
        Ok(loaded) => loaded,
        Err(problems) => {
            let failed = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The policy did not load",
                &esc(&problems.join(" ")),
                "",
            );
            return page(
                StatusCode::OK,
                tool_page(
                    title,
                    &admin.label(),
                    here,
                    &query,
                    &format!("{}\n{failed}", head(title, lead, "")),
                    "",
                ),
            );
        }
    };
    let mut teams: std::collections::BTreeMap<&str, Vec<(&str, bool)>> =
        std::collections::BTreeMap::new();
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
    let mut rows = String::new();
    for (team, people) in &mut teams {
        people.sort_unstable();
        people.dedup();
        let names: Vec<String> = people
            .iter()
            .map(|(name, admin)| {
                format!(
                    "{} {}",
                    esc(name),
                    tag(
                        if *admin { "product" } else { "" },
                        if *admin { "Admin" } else { "Member" },
                        ""
                    )
                )
            })
            .collect();
        // The rule that decides for the team's members, as the policy reads it: the first that names the team or
        // everyone. A rule naming one person may come before it for that person.
        let probe = enterplace_core::policy::Principal {
            team: (*team).to_string(),
            ..Default::default()
        };
        let rule = loaded.policy.rule_for(&probe);
        let budget = rule.and_then(|r| r.limits.budget()).map_or_else(
            || "none".to_string(),
            |b| format!("{} a {}", money(b.usd), b.per.describe()),
        );
        let rule = rule.map_or_else(
            || "none: refused".to_string(),
            |r| match &r.who {
                Who::Team(_) => esc(&r.name),
                _ => format!("{} (everyone)", esc(&r.name)),
            },
        );
        let listed = loaded.policy.teams().iter().find(|t| t.name == *team);
        let owner = listed
            .and_then(|t| t.owner.as_deref())
            .map(|o| format!(", owner {}", esc(o)))
            .unwrap_or_default();
        let _ = write!(
            rows,
            r#"<tr><td>{}<span class="g-table__sub">{}{owner}</span></td><td class="g-table__wide">{}</td><td>{rule}</td><td class="g-table__num">{budget}</td></tr>"#,
            esc(team),
            enterplace_core::count(people.len(), "key"),
            names.join("<br>"),
        );
    }
    let actions = if !admin.may(Permission::IssueKeys) {
        String::new()
    } else {
        link("Issue a key", "", "/console/people?issue=1", false)
    };
    // Only admin keys and no team the policy lists: a team comes with the first key that is not an admin's.
    let only_admins = teams
        .values()
        .all(|people| !people.is_empty() && people.iter().all(|(_, admin)| *admin));
    let table = if rows.is_empty() || only_admins {
        crate::empty_page("Teams", &crate::base(), admin.may(Permission::IssueKeys))
    } else {
        format!(
            r#"<div class="g-panel g-stack"><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm">
<thead class="t-tag"><tr><th>Team</th><th>People and workloads</th><th>Rule</th><th>Budget</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"#
        )
    };
    let main = format!("{}\n{table}", head(title, lead, &actions));
    page(
        StatusCode::OK,
        tool_page(title, &admin.label(), here, &query, &main, ""),
    )
}

// ---------------------------------------------------------------- permissions

/// Whether the person may change the policy: `edit_policy`, and not kept to one organization, since the policy
/// governs every one.
pub(crate) fn edits_policy(admin: &Admin) -> bool {
    admin.may(Permission::EditPolicy) && !admin.confined()
}

/// Whether the person may change this key: `issue_keys`, in the key's organization when kept to one.
pub(crate) fn edits_key(admin: &Admin, entry: &config::KeyEntry) -> bool {
    admin.may(Permission::IssueKeys) && admin.covers_entry(entry)
}

/// Whether the person holds every right an admin key gives, so may make one or change one.
pub(crate) fn full_admin(admin: &Admin) -> bool {
    !admin.confined() && Permission::ALL.iter().all(|p| admin.may(*p))
}

// ---------------------------------------------------------------- key fields

pub(crate) fn entry_of(console: &Console, sha256: &str) -> Option<config::KeyEntry> {
    let keys = &console.config().keys;
    let text = store::attached(keys)
        .map(|s| s.keys_text())
        .or_else(|| config::read_keys(keys).ok().flatten())?;
    config::key_entries(keys, &text)
        .ok()?
        .into_iter()
        .find(|e| e.sha256 == sha256)
}

// ---------------------------------------------------------------- versions

fn state_tag(state: &str) -> String {
    match state {
        store::LIVE => tag("allow", "Live", ""),
        store::PENDING => tag("warn", "Waiting for approval", ""),
        store::REJECTED => tag("refused", "Rejected", ""),
        _ => tag("", "Earlier", ""),
    }
}

async fn versions_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    page(
        StatusCode::OK,
        versions_body(&console, &admin, &Form::of(&uri), ""),
    )
}

fn versions_body(console: &Console, admin: &Admin, query: &Form, error: &str) -> String {
    let title = "Policy";
    let here = "/console/policy/versions";
    let lead = "Each save of the policy is a version. The live one decides every request; an earlier one can be put back in one click, as a new version.";
    let path = &console.config().policy;
    let store = match versions::store_for(path) {
        Ok(store) => store,
        Err(err) => {
            let off = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The policy is kept in the file",
                &esc(&sentence(&err.message())),
                &link("Open the policy", "", "/console/policy", false),
            );
            return tool_page(
                title,
                &admin.label(),
                here,
                query,
                &format!("{}\n{off}", head("Policy versions", lead, "")),
                "",
            );
        }
    };
    let all = store.policy_versions().unwrap_or_default();
    let selected: Option<i64> = query.get("version").parse().ok();
    let mut rows = String::new();
    for v in all.iter() {
        let decided = match (&v.decided_by, &v.decided_at) {
            (Some(by), Some(at)) => format!("{} by {}", time_full(at), esc(by)),
            _ => String::new(),
        };
        let _ = write!(
            rows,
            r#"<tr><td><a href="{here}?version={0}">Version {0}</a></td><td>{1}</td><td class="g-table__wide">{2}<span class="g-table__sub">{3}</span></td><td class="g-table__wide">{4}</td><td class="g-table__wide">{decided}</td></tr>"#,
            v.id,
            state_tag(&v.state),
            esc(&v.created_by),
            time_full(&v.created_at),
            esc(&v.note),
        );
    }
    let detail = selected
        .and_then(|id| all.iter().find(|v| v.id == id))
        .map(|v| version_detail(&store, admin, v))
        .unwrap_or_default();
    let done = match query.get("done") {
        "live" => toast("The version is live. Every gateway uses it within 2 seconds."),
        "pending" => toast("The version is saved and waits for a second admin to approve it."),
        "rejected" => toast("The version is rejected. The live version stays in force."),
        _ => String::new(),
    };
    let error = if error.is_empty() {
        String::new()
    } else {
        alert(&error.replace('\n', "<br>"))
    };
    let actions = if !edits_policy(admin) {
        link("Export YAML", "quiet", "/console/policy/export", false)
    } else {
        link("Edit the policy", "", "/console/policy/edit", false)
            + &link("Export YAML", "quiet", "/console/policy/export", false)
    };
    let main = format!(
        r#"{}
{error}
{detail}
<div class="g-panel g-stack"><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm">
<thead class="t-tag"><tr><th>Version</th><th>State</th><th>Saved</th><th>Note</th><th>Approved or rejected</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"#,
        head("Policy versions", lead, &actions)
    );
    tool_page(title, &admin.label(), here, query, &main, &done)
}

fn version_detail(
    store: &std::sync::Arc<dyn store::Store>,
    admin: &Admin,
    v: &PolicyVersion,
) -> String {
    let base = versions::base_text(store, v);
    let lines = pages::diff(&base, &v.text);
    let diff = if lines.is_empty() {
        r#"<p class="t-small g-muted" style="margin: 0">The same text as the version it was drafted on.</p>"#.to_string()
    } else {
        code(&lines)
    };
    let form = |action: &str, label: &str, kind: &str| {
        format!(
            r#"<form method="post" action="/console/policy/versions/{}/{action}" style="margin: 0">{}</form>"#,
            v.id,
            button(label, kind, "submit", "")
        )
    };
    let mut actions = String::new();
    if edits_policy(admin) {
        if v.state == store::PENDING {
            if v.created_by != admin.name {
                actions.push_str(&form("approve", "Approve and put live", ""));
            }
            actions.push_str(&form("reject", "Reject", "quiet"));
        } else if v.state != store::LIVE {
            actions.push_str(&form("rollback", "Roll back to this version", "flame"));
        }
        actions.push_str(&format!(
            r#"<form method="post" action="/console/policy/dry-run" style="margin: 0"><input type="hidden" name="text" value="{}"><input type="hidden" name="hours" value="24">{}</form>"#,
            esc(&v.text),
            button("Dry run, last 24 hours", "quiet", "submit", "")
        ));
    }
    let own = if v.state == store::PENDING && v.created_by == admin.name {
        r#"<p class="t-small g-muted" style="margin: 0">You saved this version, so another admin approves it.</p>"#
    } else {
        ""
    };
    format!(
        r#"<div class="g-panel g-stack"><div class="g-pager"><h2 class="t-md" style="margin: 0">Version {}</h2>{}</div>
{}
<h3 class="t-tag g-caps" style="margin: 0">Changes from {}</h3>
{diff}
{own}
<div class="g-head__actions">{actions}</div></div>"#,
        v.id,
        state_tag(&v.state),
        facts(&[
            ("Saved by", esc(&v.created_by)),
            ("Saved at", time_full(&v.created_at)),
            ("Note", esc(&v.note)),
            ("SHA-256", esc(&v.sha256[..16])),
        ]),
        v.base.map_or_else(
            || "nothing: the first version".to_string(),
            |b| format!("version {b}")
        ),
    )
}

async fn version_action(
    State(console): State<Console>,
    Path((id, action)): Path<(i64, String)>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let act_name: &'static str = match action.as_str() {
        "approve" => "approve_policy",
        "reject" => "reject_policy",
        "rollback" => "rollback_policy",
        _ => return redirect("/console/policy/versions"),
    };
    let back = Form::parse(&format!("version={id}"));
    if !edits_policy(&admin) {
        read_only(&console, &admin, act_name).await;
        return page(
            StatusCode::BAD_REQUEST,
            versions_body(
                &console,
                &admin,
                &back,
                "You are signed in read only: ask an admin.",
            ),
        );
    }
    let act = Act {
        action: act_name,
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "version": id }),
    };
    let done = run(
        &console,
        &act,
        move |policy, keys, by| match act_name {
            "rollback_policy" => versions::rollback(&policy, &keys, id, &by),
            name => versions::decide(&policy, &keys, id, name == "approve_policy", &by),
        },
        &admin.name,
    )
    .await;
    match done {
        Ok(v) => saved(&v),
        Err(err) => {
            let status = match err {
                Refused::Forbidden(_) => StatusCode::FORBIDDEN,
                Refused::Conflict(_) => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            page(
                status,
                versions_body(&console, &admin, &back, &esc(&sentence(&err.message()))),
            )
        }
    }
}

// ---------------------------------------------------------------- the editor and the dry run

async fn editor_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let Some(live) = live(&console) else {
        return redirect("/console/policy/versions");
    };
    if !edits_policy(&admin) {
        return redirect("/console/policy");
    }
    let query = Form::of(&uri);
    // A Start here step opens the editor with its lines already in: a draft, saved only as any edit is.
    let (text, note) = match crate::start::change(query.get("add")) {
        Some(change) => (
            crate::start::apply(&live.text, &change).0,
            "Added from Start here",
        ),
        None => (live.text.clone(), ""),
    };
    page(
        StatusCode::OK,
        editor_body(
            &console,
            &admin,
            &query,
            &text,
            Some(live.id),
            note,
            "",
            None,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn editor_body(
    console: &Console,
    admin: &Admin,
    query: &Form,
    text: &str,
    base: Option<i64>,
    note: &str,
    error: &str,
    run: Option<&DryRun>,
) -> String {
    let approval = config::load(&console.config().policy, Some(&console.config().keys))
        .is_ok_and(|l| versions::approval_needed(&l));
    let lead = if approval {
        "Edit the YAML, or load a file to import it. A save is checked as enterplace check checks a file, then waits for a second admin to approve it."
    } else {
        "Edit the YAML, or load a file to import it. A save is checked as enterplace check checks a file, then every gateway uses it within 2 seconds."
    };
    let report = run.map(dry_run_report).unwrap_or_default();
    let main = format!(
        r#"{}
{error}
{report}
<form class="g-panel g-stack" method="post" action="/console/policy/save">
<input type="hidden" name="base" value="{}">
<div class="g-field"><label class="g-field__label t-tag g-caps" for="policy-file">Import a YAML file, optional</label><input class="g-input t-body" id="policy-file" type="file" accept=".yaml,.yml,text/yaml" data-load-into="policy-text"><span class="g-field__hint t-small">Its text replaces the editor's. Nothing is saved until you save.</span></div>
<div class="g-field"><label class="g-field__label t-tag g-caps" for="policy-text">Policy</label><textarea class="g-input g-textarea t-mono" id="policy-text" name="text" rows="28" spellcheck="false" autocomplete="off">{}</textarea></div>
{}
<div class="g-field"><label class="g-field__label t-tag g-caps" for="dry-hours">Dry run over the last hours</label><input class="g-input t-mono" id="dry-hours" name="hours" type="number" min="1" max="720" value="{}" style="max-width: 10rem"></div>
<div class="g-dialog__actions">{}{}{}</div>
</form>"#,
        head("Edit the policy", lead, ""),
        base.map_or_else(|| "none".to_string(), |b| b.to_string()),
        esc(text),
        field(&Field {
            id: "policy-note",
            name: "note",
            label: "What changed, for the history",
            value: note,
            mono: false,
            extra: r#" autocomplete="off" maxlength="500""#,
            hint: "",
            error: "",
        }),
        query
            .get("hours")
            .parse::<u64>()
            .unwrap_or(24)
            .clamp(1, 720),
        link("Cancel", "quiet", "/console/policy", false),
        button(
            "Dry run",
            "quiet",
            "submit",
            r#" formaction="/console/policy/dry-run""#
        ),
        button(
            if approval {
                "Save for approval"
            } else {
                "Save version"
            },
            "",
            "submit",
            ""
        )
    );
    tool_page(
        "Policy",
        &admin.label(),
        "/console/policy/edit",
        query,
        &main,
        "",
    )
}

fn dry_run_report(run: &DryRun) -> String {
    let table = |title: &str, list: &[versions::Replayed]| {
        if list.is_empty() {
            return format!(r#"<p class="t-small g-muted" style="margin: 0">{title}: none.</p>"#);
        }
        let rows: String = list
            .iter()
            .take(200)
            .map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}<span class=\"g-table__sub\">{}</span></td><td>{}</td><td>{} to {}</td><td class=\"g-table__wide\">{} to {}</td></tr>",
                    time_list(&r.time),
                    esc(&r.person),
                    esc(&r.team),
                    esc(&r.model),
                    esc(&r.was),
                    esc(&r.now),
                    esc(if r.rule_was.is_empty() { "none" } else { &r.rule_was }),
                    esc(if r.rule_now.is_empty() { "none" } else { &r.rule_now }),
                )
            })
            .collect();
        format!(
            r#"<h3 class="t-tag g-caps" style="margin: 0">{title}: {}</h3><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm"><thead class="t-tag"><tr><th>Time</th><th>Who</th><th>Model</th><th>Decision</th><th>Rule</th></tr></thead><tbody>{rows}</tbody></table></div>"#,
            list.len()
        )
    };
    let changed = run.now_refused.len() + run.now_allowed.len() + run.other_rule.len();
    format!(
        r#"<div class="g-panel g-stack"><div class="g-pager"><h2 class="t-md" style="margin: 0">Dry run</h2>{}</div>
<p class="t-body" style="margin: 0">{} replayed since {}, {} changed. {} refused before the policy decided (a key, a budget, a guardrail, a kill switch) and not replayed.</p>
<p class="t-small g-muted" style="margin: 0">{}</p>
{}{}{}</div>"#,
        if changed == 0 {
            tag("allow", "No change", "")
        } else {
            tag("warn", "Changes", "")
        },
        enterplace_core::count(run.replayed, "request"),
        time_full(&run.since),
        changed,
        enterplace_core::count(run.skipped, "request"),
        esc(&run.note),
        table("Now refused", &run.now_refused),
        table("Now allowed", &run.now_allowed),
        table("Allowed by another rule", &run.other_rule),
    )
}

async fn save(State(console): State<Console>, headers: HeaderMap, body: String) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    // A browser sends a textarea's line breaks as CRLF.
    let text = form.get("text").replace("\r\n", "\n");
    let (base, note) = (base_of(&form), form.get("note").trim().to_string());
    let back = |err: &Refused| {
        page(
            StatusCode::BAD_REQUEST,
            editor_body(
                &console,
                &admin,
                &form,
                &text,
                base,
                &note,
                &problems(err),
                None,
            ),
        )
    };
    if !edits_policy(&admin) {
        read_only(&console, &admin, "propose_policy").await;
        return back(&Refused::Forbidden(
            "you are signed in read only: ask an admin to change the policy.".into(),
        ));
    }
    match save_version(
        &console,
        &admin,
        "propose_policy",
        text.clone(),
        base,
        note.clone(),
    )
    .await
    {
        Ok(v) => saved(&v),
        Err(err) => back(&err),
    }
}

async fn dry_run(State(console): State<Console>, headers: HeaderMap, body: String) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let text = form.get("text").replace("\r\n", "\n");
    let base = base_of(&form).or_else(|| live(&console).map(|v| v.id));
    let note = form.get("note").trim().to_string();
    let hours = form.get("hours").parse::<u64>().unwrap_or(24).clamp(1, 720);
    let act = Act {
        action: "dry_run_policy",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "hours": hours, "sha256": enterplace_core::id::sha256_hex(text.as_bytes()) }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            editor_body(
                &console,
                &admin,
                &form,
                &text,
                base,
                &note,
                &alert(NOT_RECORDED),
                None,
            ),
        );
    }
    let c = console.config();
    let (policy, keys, draft) = (c.policy.clone(), c.keys.clone(), text.clone());
    let stopped = |err: tokio::task::JoinError| {
        Refused::Store(format!("the dry run stopped: {err}. Try again."))
    };
    let checked = tokio::task::spawn_blocking(move || {
        let loaded = config::load(&policy, Some(&keys)).map_err(Refused::Invalid)?;
        let checked = versions::check(&policy, &keys, &draft, &loaded).map_err(Refused::Invalid)?;
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
        Ok(run) => page(
            StatusCode::OK,
            editor_body(&console, &admin, &form, &text, base, &note, "", Some(&run)),
        ),
        Err(err) => page(
            StatusCode::BAD_REQUEST,
            editor_body(
                &console,
                &admin,
                &form,
                &text,
                base,
                &note,
                &problems(&err),
                None,
            ),
        ),
    }
}

async fn export(State(console): State<Console>, headers: HeaderMap) -> Response {
    if console.admin(&headers).await.is_none() {
        return redirect("/console/sign-in");
    }
    match config::policy_text(&console.config().policy) {
        Ok(text) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"enterplace.policy.yaml\"",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            text,
        )
            .into_response(),
        Err(err) => page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::notice(
                "The policy could not be read",
                &esc(&err),
                "/console/policy",
                "Open the policy",
            ),
        ),
    }
}
