//! Budget raises: a person asks for more room on a budget until a time (`POST /v1/budget/raises`), an admin
//! approves it for an amount and a window or rejects it (`/admin/budget/raises`), and while it runs every budget
//! of its scope is that much larger. It ends by itself. Kept in the store when there is one, so every gateway
//! applies it within a poll; in a file beside the keys file otherwise.

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use axum::http::{Method, StatusCode};
use gantry_core::{
    audit, config, id,
    policy::{Applied, Limit, Policy, Principal, Role, Who},
    store::{APPROVED, PENDING, REJECTED, Raise, Store},
};
use serde_json::{Value, json};

use crate::{Refusal, admin::refused};

/// The app-facing routes.
pub(crate) const RAISES: &str = "/v1/budget/raises";

/// Most raises one person may have waiting for a decision.
const MAX_PENDING: usize = 20;

pub(crate) struct Raises {
    store: Option<Arc<dyn Store>>,
    file: Option<PathBuf>,
    local: RwLock<Arc<Vec<Raise>>>,
}

impl Raises {
    /// The raises of `store` when it keeps them, else those in `file` (read now, written at each change).
    pub(crate) fn open(store: Option<Arc<dyn Store>>, file: Option<PathBuf>) -> Self {
        let kept = file
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            store,
            file,
            local: RwLock::new(Arc::new(kept)),
        }
    }

    pub(crate) fn all(&self) -> Arc<Vec<Raise>> {
        if let Some(shared) = self.store.as_ref().and_then(|store| store.raises()) {
            return shared;
        }
        self.local
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Adds a raise or replaces the one with its id. Blocks on the store or the file.
    pub(crate) fn put(&self, raise: &Raise) -> Result<(), String> {
        if let Some(store) = self.store.as_ref().filter(|s| s.raises().is_some()) {
            return store.put_raise(raise);
        }
        let mut local = self
            .local
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut all: Vec<Raise> = local.iter().filter(|r| r.id != raise.id).cloned().collect();
        all.push(raise.clone());
        if let Some(path) = &self.file {
            let text = serde_json::to_vec_pretty(&all).map_err(|err| err.to_string())?;
            std::fs::write(path, text).map_err(|err| {
                format!(
                    "the budget raises could not be written to {}: {err}. Nothing was changed. Check the file's permissions.",
                    path.display()
                )
            })?;
        }
        *local = Arc::new(all);
        Ok(())
    }

    /// [`apply`](Self::apply) for the explanation's limits, which are JSON: each raised budget shows its raised
    /// amount, and the raises that make it up.
    pub(crate) fn explain(&self, limits: &mut [Value]) {
        let all = self.all();
        let now = audit::timestamp();
        for limit in limits
            .iter_mut()
            .filter(|l| l["limit"] == "budget" && l["of"] != "session")
        {
            let scope = limit["scope"].as_str().unwrap_or_default().to_string();
            for raise in all.iter().filter(|r| r.active(&now)) {
                let models = scope
                    .strip_prefix(raise.scope.as_str())
                    .is_some_and(|rest| rest.starts_with(" models:"));
                if scope != raise.scope && !models {
                    continue;
                }
                limit["usd"] = (limit["usd"].as_f64().unwrap_or(0.0) + raise.usd).into();
                limit["source"] = format!(
                    "{}, raised by ${} until {} (raise {})",
                    limit["source"].as_str().unwrap_or_default(),
                    raise.usd,
                    raise.until,
                    raise.id
                )
                .into();
            }
        }
    }

    /// Adds every raise running now to the budgets of its scope, and names it where the budget is written, so
    /// the explanation and a refusal's record show it.
    pub(crate) fn apply(&self, applied: &mut [Applied]) {
        let all = self.all();
        if all.is_empty() {
            return;
        }
        let now = audit::timestamp();
        for a in applied.iter_mut().filter(|a| a.of != "session") {
            let Limit::Budget(budget) = &mut a.limit else {
                continue;
            };
            for raise in all.iter().filter(|r| r.active(&now)) {
                // A rule's budget for some models only is kept under its scope and the models.
                let models = a
                    .scope
                    .strip_prefix(raise.scope.as_str())
                    .is_some_and(|rest| rest.starts_with(" models:"));
                if a.scope == raise.scope || models {
                    budget.usd += raise.usd;
                    a.source = format!(
                        "{}, raised by ${} until {} (raise {})",
                        a.source, raise.usd, raise.until, raise.id
                    );
                }
            }
        }
    }
}

fn bad(message: impl std::fmt::Display) -> Refusal {
    refused(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        format!("Refused: {message}"),
    )
}

/// The amount, end and reason of a raise as sent, checked. `until` is a UTC date or time still ahead.
fn terms(sent: &Value, needs_reason: bool) -> Result<(f64, String, String), Refusal> {
    const SHAPE: &str = "Send {\"usd\": 500, \"until\": \"2026-12-31\", \"reason\": \"quarter-end backfill\"}: usd above 0, until a UTC date or time still ahead, and why.";
    let usd = sent["usd"].as_f64().filter(|n| n.is_finite() && *n > 0.0);
    let until = sent["until"]
        .as_str()
        .filter(|t| config::valid_expiry(t))
        .filter(|t| !gantry_core::policy::expiry_passed(t, &audit::timestamp()));
    let reason = sent["reason"].as_str().unwrap_or_default().trim();
    let reason_ok = reason.chars().count() <= 500
        && !reason.chars().any(char::is_control)
        && (!needs_reason || !reason.is_empty());
    match (usd, until, reason_ok) {
        (Some(usd), Some(until), true) => Ok((usd, until.to_string(), reason.to_string())),
        _ => Err(bad(format!(
            "a budget raise needs an amount, an end and a reason of at most 500 characters on one line. {SHAPE}"
        ))),
    }
}

/// `GET /v1/budget/raises` lists the caller's own raises; `POST` asks for one, which waits for an admin. The scope
/// is the caller's team when their rule budgets by team, else the caller; `"scope": "team" | "person" | "key"`
/// picks another of the caller's own. Returns the answer and what its record keeps.
pub(crate) fn requested(
    raises: &Raises,
    policy: &Policy,
    person: &Principal,
    method: &Method,
    body: &[u8],
) -> Result<(StatusCode, Value, Option<Value>), Refusal> {
    if method == Method::GET {
        let own: Vec<Raise> = raises
            .all()
            .iter()
            .filter(|r| r.requested_by == person.name)
            .cloned()
            .collect();
        return Ok((StatusCode::OK, json!({ "raises": own }), None));
    }
    let sent: Value =
        serde_json::from_slice(body).map_err(|err| bad(format!("send a JSON body ({err}).")))?;
    let (usd, until, reason) = terms(&sent, true)?;
    let by_team = policy
        .rule_for(person)
        .is_some_and(|rule| matches!(rule.who, Who::Team(_)));
    let scope = match sent["scope"].as_str() {
        Some("team") => person.team_scope(),
        None if by_team => person.team_scope(),
        Some("person") | None => person.person_scope(),
        Some("key") => format!("key:{}", person.key),
        Some(other) => {
            return Err(bad(format!(
                "scope is \"{other}\". It is team, person or key: whose budget the raise is for. Leave it out for the one your rule counts."
            )));
        }
    };
    let pending = raises
        .all()
        .iter()
        .filter(|r| r.requested_by == person.name && r.state == PENDING)
        .count();
    if pending >= MAX_PENDING {
        return Err(refused(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_raises",
            format!(
                "Refused: \"{}\" has {pending} budget raises waiting for a decision, the most one person may have. Ask a Gantry admin to decide them.",
                person.name
            ),
        ));
    }
    let raise = Raise {
        id: format!("raise_{}", id::random_hex(6)),
        scope,
        usd,
        until,
        reason,
        requested_by: person.name.clone(),
        requested_at: audit::timestamp(),
        state: PENDING.into(),
        decided_by: None,
        decided_at: None,
    };
    raises.put(&raise).map_err(|err| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            format!("Refused: {err}"),
        )
    })?;
    let kept = serde_json::to_value(&raise).unwrap_or_default();
    Ok((StatusCode::CREATED, kept.clone(), Some(kept)))
}

/// Whether a role kept to part of the install may see and decide raises of `scope`: its own teams' only.
fn in_reach(role: &Role, scope: &str) -> bool {
    if !role.confined() {
        return true;
    }
    let Some(team) = scope.strip_prefix("team:") else {
        return false;
    };
    let (org, team) = team.split_once('/').unwrap_or(("", team));
    role.customers.is_empty()
        && role.org.as_deref().is_none_or(|o| o == org)
        && (role.teams.is_empty() || role.teams.iter().any(|t| t == team))
}

/// `GET /admin/budget/raises`: every raise within the role's reach, the ones waiting first.
pub(crate) fn listed(raises: &Raises, role: &Role) -> Value {
    let mut all: Vec<Raise> = raises
        .all()
        .iter()
        .filter(|r| in_reach(role, &r.scope))
        .cloned()
        .collect();
    all.sort_by_key(|r| {
        (
            r.state != PENDING,
            std::cmp::Reverse(r.requested_at.clone()),
        )
    });
    json!({ "raises": all })
}

/// What an admin call makes of a raise: `add_budget_raise` a new one, approved at once; `approve_budget_raise`
/// and `reject_budget_raise` a decision on the waiting raise `id`, the approval for the amount and end asked for
/// unless the admin sends others. Nothing is written here.
pub(crate) fn decided(
    raises: &Raises,
    role: &Role,
    action: &str,
    id: &str,
    sent: &Value,
    by: &str,
) -> Result<Raise, Refusal> {
    let out_of_reach = |scope: &str| {
        refused(
            StatusCode::FORBIDDEN,
            "not_permitted",
            format!(
                "Refused: role \"{}\" is kept to {}, and this raise is for {scope}. Ask an admin of the whole install.",
                role.name,
                crate::admin::reach(role)
            ),
        )
    };
    let now = audit::timestamp();
    if action == "add_budget_raise" {
        let (usd, until, reason) = terms(sent, true)?;
        let scope = sent["scope"].as_str().unwrap_or_default();
        let known = [
            "team:",
            "person:",
            "key:",
            "customer:",
            "tag:",
            "model:",
            "model_group:",
            "org:",
        ];
        if (scope != "global"
            && !known
                .iter()
                .any(|k| scope.len() > k.len() && scope.starts_with(k)))
            || scope.len() > 200
            || scope.chars().any(char::is_control)
        {
            return Err(bad(
                "scope names the counter whose budgets the raise is for, as GET /admin/explain shows it: team:<team>, person:<name>, key:<8 hex>, customer:<name>, tag:<tag>, model:<model>, model_group:<group>, org:<org> or global. In an install with organizations a name is <org>/<name>.",
            ));
        }
        if !in_reach(role, scope) {
            return Err(out_of_reach(scope));
        }
        return Ok(Raise {
            id: format!("raise_{}", id::random_hex(6)),
            scope: scope.to_string(),
            usd,
            until,
            reason,
            requested_by: by.to_string(),
            requested_at: now.clone(),
            state: APPROVED.into(),
            decided_by: Some(by.to_string()),
            decided_at: Some(now),
        });
    }
    let all = raises.all();
    let Some(raise) = all.iter().find(|r| r.id == id) else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "no_such_raise",
            format!(
                "Refused: there is no budget raise \"{id}\". GET /admin/budget/raises lists them."
            ),
        ));
    };
    if !in_reach(role, &raise.scope) {
        return Err(out_of_reach(&raise.scope));
    }
    if raise.state != PENDING {
        return Err(refused(
            StatusCode::CONFLICT,
            "raise_decided",
            format!(
                "Refused: raise {id} is {} already, by {}. A decision is made once: add a new raise with POST /admin/budget/raises to change it.",
                raise.state,
                raise.decided_by.as_deref().unwrap_or("an admin")
            ),
        ));
    }
    let mut raise = raise.clone();
    if action == "approve_budget_raise" {
        // The admin's own amount and end, when sent, over what was asked for.
        let asked = json!({
            "usd": sent.get("usd").cloned().unwrap_or(raise.usd.into()),
            "until": sent.get("until").cloned().unwrap_or(raise.until.clone().into()),
        });
        let (usd, until, _) = terms(&asked, false)?;
        (raise.usd, raise.until, raise.state) = (usd, until, APPROVED.into());
    } else {
        raise.state = REJECTED.into();
    }
    raise.decided_by = Some(by.to_string());
    raise.decided_at = Some(now);
    Ok(raise)
}
