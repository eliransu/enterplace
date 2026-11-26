//! What the policy's pages share: the live version, saving a new one (recorded first, then checked and made), who
//! may change the policy or a key, and the YAML export. The raw policy, its versions, the editor and the dry run
//! moved to the console app (`raw_policy.rs`), Teams to its Teams page (`teams.rs`), a key's fields to its People
//! page (`people.rs`), prices to its Prices page (`prices.rs`).
//!
//! The policy changes only when it is kept in the store (`store.policy_from: store`): each save is a new version,
//! checked as `enterplace check` checks a file, recorded in the audit chain first, and live on every gateway within
//! 2 seconds, or waiting for a second admin when the live version sets `store.approval: true`.

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use enterplace_core::{
    config,
    policy::Permission,
    store::{self, PolicyVersion},
    versions::{self, Refused},
};
use serde_json::{Map, Value, json};

use crate::{Act, Admin, Console, NOT_RECORDED, html::esc, page, pages, record, redirect};

pub(crate) fn routes() -> Router<Console> {
    Router::new().route("/policy/export", get(export))
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

/// How long a save waits for the gateways to report on what it saved: a gateway reads a new version within a
/// second, checks for it every second and writes its heartbeat every 2.
const REPORT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Where a saved policy is in force, said after waiting a few seconds for the gateways to report: on how many of
/// the healthy gateways (store's `version`), or whether the gateway serving the file runs it (`sha256` of the text
/// written), and the reason of each gateway that refused it. A save is never said to be in force where it is not.
pub(crate) async fn in_force(console: &Console, version: Option<i64>, sha256: &str) -> String {
    let start = std::time::Instant::now();
    if let Some(id) = version {
        let Some(store) = console.store() else {
            return format!("Saved as version {id}.");
        };
        loop {
            let replicas = store.replicas().await.unwrap_or_default();
            let (n, m, refusals) = spread(&replicas, id);
            if m == 0 {
                // A gateway that just started writes its first heartbeat within 2 seconds.
                if start.elapsed() >= REPORT_WAIT {
                    return format!(
                        "Saved as version {id}. No gateway has written a heartbeat in 10 seconds, so none is known to run it yet: Policy, Versions shows where it is in force."
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                continue;
            }
            let settled = n + refusals.len() >= m;
            if settled || start.elapsed() >= REPORT_WAIT {
                return match refusals.first() {
                    Some((host, why)) => format!(
                        "Saved as version {id}, and {host} refused it: {why} In force on {n} of {m} gateways; the others keep the version they ran. Fix the cause on {host} (or save a version it can run)."
                    ),
                    None if settled => format!("Saved; in force on {n} of {m} gateways."),
                    None => format!(
                        "Saved as version {id}; in force on {n} of {m} gateways so far. The others have not reported yet: Policy, Versions shows where it is in force."
                    ),
                };
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
    let path = &console.config().policy;
    loop {
        let Some(state) = store::in_force(path) else {
            // No gateway serves this file in this process (the console runs on its own): nothing to wait for.
            return "Saved. The gateway reading this file uses it within 2 seconds.".into();
        };
        if state.sha256 == sha256 {
            return "Saved; in force on the gateway.".into();
        }
        if let Some((_, _, why)) = state.refused.as_ref().filter(|(s, _, _)| s == sha256) {
            return format!(
                "Saved to {}, and the gateway refused it, so it keeps the policy it had: {why} Fix the cause, or put the earlier version back under Policy, Versions.",
                path.display()
            );
        }
        if start.elapsed() >= REPORT_WAIT {
            return format!(
                "Saved to {}. The gateway has not loaded it yet: Policy, Versions shows whether it runs it.",
                path.display()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// How many healthy gateways run version `id`, how many are healthy, and each healthy one that refused it.
pub(crate) fn spread(
    replicas: &[store::Replica],
    id: i64,
) -> (usize, usize, Vec<(String, String)>) {
    let healthy: Vec<&store::Replica> = replicas.iter().filter(|r| r.healthy).collect();
    let n = healthy
        .iter()
        .filter(|r| r.policy_version == Some(id))
        .count();
    let refusals = healthy
        .iter()
        .filter(|r| r.refused_version == Some(id) && r.policy_version != Some(id))
        .map(|r| (gateway_name(r), r.refused.clone().unwrap_or_default()))
        .collect();
    (n, healthy.len(), refusals)
}

/// A gateway as the console names it: its host, else its name on the store.
pub(crate) fn gateway_name(r: &store::Replica) -> String {
    if r.host.is_empty() {
        r.gateway.clone()
    } else {
        r.host.clone()
    }
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

// ---------------------------------------------------------------- preview before a save

tokio::task_local! {
    /// Whether the request asks for a preview (`X-Enterplace-Preview`): the change is drafted and checked, and
    /// nothing is recorded or saved.
    static PREVIEW: bool;
}

/// Runs each console request with whether it asks for a preview, so every save path sees it without a parameter.
pub(crate) async fn preview_scope(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let asked = request.headers().contains_key("x-enterplace-preview");
    PREVIEW.scope(asked, next.run(request)).await
}

pub(crate) fn previewing() -> bool {
    PREVIEW.try_with(|p| *p).unwrap_or(false)
}

/// The answer to a preview: `after` checked as `enterplace check` checks a file, its diff against `before` (the
/// policy in force), and what it removes. Nothing is recorded or saved.
pub(crate) async fn preview(
    console: &Console,
    before: String,
    after: String,
) -> crate::api::Answer {
    let c = console.config();
    let (policy, keys, draft) = (c.policy.clone(), c.keys.clone(), after.clone());
    tokio::task::spawn_blocking(move || {
        let loaded = config::load(&policy, Some(&keys)).map_err(Refused::Invalid)?;
        versions::check(&policy, &keys, &draft, &loaded)
            .map(|_| ())
            .map_err(Refused::Invalid)
    })
    .await
    .unwrap_or_else(|err| {
        Err(Refused::Store(format!(
            "the check stopped: {err}. Try again."
        )))
    })
    .map_err(|err| crate::api::refused(&err))?;
    let diff: Vec<Value> = versions::diff(&before, &after)
        .into_iter()
        .map(|(n, text, kind)| json!({ "n": n, "text": text, "kind": kind }))
        .collect();
    Ok(crate::api::ok(json!({
        "message": "Check the change, then apply it.",
        "preview": { "diff": diff, "text": after, "removes": removed(&before, &after) },
    })))
}

/// What `after` drops that `before` has, in words: each named rule, guardrail, alias, provider and MCP server, and
/// the number of limits.
pub(crate) fn removed(before: &str, after: &str) -> Vec<String> {
    let (Ok(old), Ok(new)) = (versions::tree(before), versions::tree(after)) else {
        return Vec::new();
    };
    let items = |tree: &Map<String, Value>, list: &str| -> Vec<Value> {
        tree.get(list)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let name = |v: &Value| v.get("name").and_then(Value::as_str).map(str::to_string);
    let mut out = Vec::new();
    for (list, what) in [
        ("rules", "Rule"),
        ("guardrails", "Guardrail"),
        ("aliases", "Alias"),
        ("providers", "Provider"),
        ("mcp", "MCP server"),
    ] {
        let kept: Vec<String> = items(&new, list).iter().filter_map(name).collect();
        for gone in items(&old, list).iter().filter_map(name) {
            if !kept.contains(&gone) {
                out.push(format!("{what} {gone}"));
            }
        }
    }
    let kept = items(&new, "limits");
    let gone = items(&old, "limits")
        .iter()
        .filter(|l| !kept.contains(l))
        .count();
    if gone > 0 {
        out.push(enterplace_core::count(gone, "limit"));
    }
    out
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

#[cfg(test)]
mod tests {
    use super::removed;

    #[test]
    fn names_what_a_change_removes() {
        let before = "guardrails:\n  - name: no-secrets\n    type: secrets\n  - name: no-pii\n    type: pii\nlimits:\n  - team: payments\n    rate: { rpm: 10 }\n  - global: true\n    rate: { rpm: 100 }\n";
        let after = "guardrails:\n  - name: no-pii\n    type: pii\nlimits:\n  - global: true\n    rate: { rpm: 100 }\n";
        assert_eq!(
            removed(before, after),
            vec!["Guardrail no-secrets".to_string(), "1 limit".to_string()]
        );
        assert!(removed(after, before).is_empty());
    }
}
