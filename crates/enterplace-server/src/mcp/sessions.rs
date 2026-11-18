//! The MCP sessions of this gateway, for an admin: which clients are connected as whom, and which people have
//! connected their own account to which server. Either can be ended: the client connects again, the person signs
//! in again. Served as `/admin/mcp/sessions` and as the console app's MCP sessions page.
// ponytail: client sessions are this gateway's own, in memory, as what a client said it supports is; behind several
// gateways each lists and ends its own. Keep them in the store when sessions must be ended install-wide.

use serde_json::{Value, json};

use super::{Mcp, lock};

pub(super) const SESSIONS: &str = "MCP sessions";

/// Who may see a session: everyone, or a role kept to an organization and teams.
pub(crate) struct Reach<'a> {
    pub org: Option<&'a str>,
    pub teams: &'a [String],
    /// A role kept to end customers sees no session: a session belongs to a person, not to a customer.
    pub customers: bool,
}

impl Reach<'_> {
    fn covers(&self, org: &str, team: &str) -> bool {
        !self.customers
            && self.org.is_none_or(|o| o == org)
            && (self.teams.is_empty() || self.teams.iter().any(|t| t == team))
    }
}

impl Mcp {
    /// Every client session and every person's connection to a server, within `reach`.
    pub(crate) async fn sessions(&self, reach: &Reach<'_>) -> Value {
        let mut sessions: Vec<Value> = lock(&self.callers)
            .iter()
            .filter(|(id, s)| reach.covers(&s.org, &s.team) && !lock(&self.revoked).contains(*id))
            .map(|(id, s)| {
                json!({
                    // Enough of the id to end the session by; the whole id is the client's alone.
                    "id": id.chars().take(12).collect::<String>(),
                    "person": s.person,
                    "team": s.team,
                    "client": s.client_name,
                    "client_version": s.client_version,
                    "user_agent": s.user_agent,
                    "oauth_client": s.oauth_client,
                    "bundle": s.bundle,
                    "started": s.started,
                    "last_used": s.last_used,
                })
            })
            .collect();
        sessions.sort_by(|a, b| b["last_used"].as_str().cmp(&a["last_used"].as_str()));
        let mut connections = Vec::new();
        // A connection names a person only, so a role kept to part of the install is shown none.
        if reach.org.is_none() && reach.teams.is_empty() && !reach.customers {
            for (id, value) in self.keep.list("cred").await.unwrap_or_default() {
                if let Some((server, person)) = id.split_once('/') {
                    connections.push(json!({
                        "id": format!("{server}:{person}"),
                        "server": server,
                        "person": person,
                        "connected": value["at"],
                    }));
                }
            }
        }
        json!({"sessions": sessions, "connections": connections})
    }

    /// Ends a client session (by the id the list shows) or a person's connection to a server (`<server>:<person>`).
    /// Returns what was ended, for the record, or `None` when nothing has that id.
    pub(crate) async fn end_session(&self, id: &str, reach: &Reach<'_>) -> Option<Value> {
        if let Some((server, person)) = id.split_once(':') {
            if reach.org.is_some() || !reach.teams.is_empty() || reach.customers {
                return None;
            }
            let taken = self.keep.take("cred", &format!("{server}/{person}")).await;
            if !matches!(taken, Ok(Some(_))) {
                return None;
            }
            // The session Enterplace holds at the server with that credential goes with it.
            if let Some(upstream) = self.servers().iter().find(|s| s.name == server) {
                lock(&upstream.sessions).remove(person);
            }
            return Some(json!({"connection": id, "server": server, "person": person}));
        }
        if id.len() < 12 {
            return None;
        }
        let mut callers = lock(&self.callers);
        let full = callers
            .iter()
            .find(|(full, s)| full.starts_with(id) && reach.covers(&s.org, &s.team))
            .map(|(full, _)| full.clone())?;
        let ended = callers.remove(&full)?;
        let mut revoked = lock(&self.revoked);
        if revoked.len() >= super::MAX_REMEMBERED {
            revoked.clear();
        }
        revoked.insert(full);
        Some(
            json!({"session": id, "person": ended.person, "team": ended.team, "client": ended.client_name}),
        )
    }
}

pub(super) fn reach_of(admin: &enterplace_console::Admin) -> Reach<'_> {
    Reach {
        org: admin.org.as_deref(),
        teams: &admin.teams,
        customers: !admin.customers.is_empty(),
    }
}
