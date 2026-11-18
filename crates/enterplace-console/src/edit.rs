//! Teams, and what the policy's other pages share: the live version, saving a new one (recorded first, then checked
//! and made), who may change the policy or a key, and the YAML export. The raw policy, its versions, the editor and
//! the dry run moved to the console app (`raw_policy.rs`), a key's fields to its People page (`people.rs`), prices to
//! its Prices page (`prices.rs`).
//!
//! The policy changes only when it is kept in the store (`store.policy_from: store`): each save is a new version,
//! checked as `enterplace check` checks a file, recorded in the audit chain first, and live on every gateway within
//! 2 seconds, or waiting for a second admin when the live version sets `store.approval: true`.

use std::fmt::Write as _;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use enterplace_core::{
    config,
    policy::{Permission, Who},
    store::{self, PolicyVersion},
    versions::{self, Refused},
};
use serde_json::json;

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED,
    figures::money,
    html::{empty, esc, head, link, motif, tag},
    page,
    pages::{self, tool_page},
    record, redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        .route("/teams", get(teams_page))
        .route("/policy/export", get(export))
}

/// The live version, when the policy is kept in the store.
pub(crate) fn live(console: &Console) -> Option<PolicyVersion> {
    store::policy_store(&console.config().policy).and_then(|s| s.live_policy())
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
pub(crate) async fn run(
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
