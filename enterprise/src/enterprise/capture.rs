//! Prompt and answer text for the export destinations that opt in to it (license feature `siem`).
//!
//! The audit log never holds text, so text cannot come from it. It is taken at request time through the gateway's
//! `Capture` hook, and only while at least one destination has opted in (for the teams it names, or everyone).
//! Before it is stored it is redacted by Enterplace's own secrets and PII detectors (`enterplace_core::guard`, every finding
//! replaced by `[MASKED kind]`); text the detectors cannot check is dropped, not kept. It is stored encrypted with
//! ENTERPLACE_EXPORT_KEY in `enterprise_captures`, apart from the audit chain, and deleted after `capture_hours` (24 by
//! default, at most 168) whether or not it was sent. Destinations without the opt-in never get it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, RwLock};

use enterplace_core::guard::{self, Action, Check, Guardrail, On};
use enterplace_server::{Capture, Captured};
use serde_json::{Value, json};

use super::Db;
use super::siem::sinks::{Dest, Text};

pub const MIGRATION: &str = "
CREATE TABLE enterprise_captures (
    decision text PRIMARY KEY,
    replica text NOT NULL,
    team text NOT NULL,
    sealed text NOT NULL,
    captured_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX enterprise_captures_expires ON enterprise_captures (expires_at);
ALTER TABLE enterprise_export_settings ADD COLUMN capture_hours integer NOT NULL DEFAULT 24;
CREATE INDEX enterprise_audit_decision ON enterprise_audit (replica, ((line::jsonb)->>'id'));
";

/// Most requests waiting between two exporter ticks (one second). Past it text is dropped, never the request.
const QUEUE: usize = 10_000;
pub const HOURS_MAX: i32 = 168;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Want {
    Nobody,
    All,
    Teams(Vec<String>),
}

/// The gateway's capture hook for this replica, and the queue between it and the database.
pub struct Captures {
    tx: SyncSender<Captured>,
    rx: Mutex<Receiver<Captured>>,
    want: RwLock<Want>,
    dropped: AtomicBool,
}

impl Default for Captures {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE);
        Self {
            tx,
            rx: Mutex::new(rx),
            want: RwLock::new(Want::Nobody),
            dropped: AtomicBool::new(false),
        }
    }
}

impl Capture for Captures {
    fn wanted(&self, team: &str) -> bool {
        match &*self
            .want
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            Want::Nobody => false,
            Want::All => true,
            Want::Teams(teams) => teams.iter().any(|t| t == team),
        }
    }

    fn take(&self, captured: Captured) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(captured) {
            if !self.dropped.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "enterplace: prompt capture is behind and dropped text of some requests; the requests themselves are unaffected. Check that Postgres keeps up."
                );
            }
        }
    }
}

/// Whether a destination opted in to text, and for which teams (empty: everyone).
pub fn opted_in(dest: &Dest) -> Option<Vec<String>> {
    if !dest.kind.per_request() || dest.options["text"] != true {
        return None;
    }
    Some(teams(
        dest.options["text_teams"].as_str().unwrap_or_default(),
    ))
}

pub fn teams(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether a request of `team` may go with its text to `dest`.
pub fn for_dest(dest: &Dest, team: &str) -> bool {
    opted_in(dest).is_some_and(|teams| teams.is_empty() || teams.iter().any(|t| t == team))
}

impl Captures {
    /// Captures for the teams the destinations opted in for: none when no destination did.
    pub fn set(&self, dests: &[Dest]) {
        let mut want = Want::Nobody;
        for teams in dests.iter().filter_map(opted_in) {
            want = match (want, teams.is_empty()) {
                (_, true) | (Want::All, _) => Want::All,
                (Want::Nobody, false) => Want::Teams(teams),
                (Want::Teams(mut have), false) => {
                    have.extend(teams);
                    Want::Teams(have)
                }
            };
        }
        *self
            .want
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = want;
    }

    /// Stores what was captured since the last call: redacted, encrypted, with its expiry. Returns how many.
    pub async fn flush(
        &self,
        db: &Db,
        replica: &str,
        key: Option<&[u8; 32]>,
        hours: i32,
    ) -> Result<usize, String> {
        let taken: Vec<Captured> = {
            let rx = self
                .rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            rx.try_iter().collect()
        };
        if taken.is_empty() {
            return Ok(0);
        }
        // Without the key nothing can be stored encrypted, so nothing is stored: the page says so.
        let Some(key) = key else {
            return Ok(0);
        };
        let key = *key;
        let rows = tokio::task::spawn_blocking(move || {
            taken
                .into_iter()
                .filter_map(|c| {
                    let text = redact(&Text {
                        prompt: c.prompt(),
                        answer: c.answer_text(),
                    })?;
                    let json = serde_json::to_string(&text).ok()?;
                    let sealed = super::siem::seal_secret(&key, &json).ok()?;
                    Some((c.decision, c.team, sealed))
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|err| format!("prompt capture stopped: {err}"))?;
        let client = db.client().await?;
        for (decision, team, sealed) in &rows {
            client
                .execute(
                    "INSERT INTO enterprise_captures (decision, replica, team, sealed, expires_at) \
                     VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5)) ON CONFLICT (decision) DO NOTHING",
                    &[decision, &replica, team, sealed, &hours],
                )
                .await
                .map_err(super::siem::db_error)?;
        }
        self.dropped.store(false, Ordering::Relaxed);
        Ok(rows.len())
    }
}

/// Deletes text past its expiry. Returns how many.
pub async fn prune(db: &Db) -> Result<u64, String> {
    let client = db.client().await?;
    client
        .execute(
            "DELETE FROM enterprise_captures WHERE expires_at < now()",
            &[],
        )
        .await
        .map_err(super::siem::db_error)
}

/// The stored text of these decisions, with each one's team, opened with the key. Text that does not open is left
/// out.
pub async fn texts(
    db: &Db,
    key: Option<&[u8; 32]>,
    ids: &[String],
) -> Result<HashMap<String, (String, Text)>, String> {
    if ids.is_empty() || key.is_none() {
        return Ok(HashMap::new());
    }
    let client = db.client().await?;
    let rows = client
        .query(
            "SELECT decision, team, sealed FROM enterprise_captures WHERE decision = ANY($1) AND expires_at >= now()",
            &[&ids],
        )
        .await
        .map_err(super::siem::db_error)?;
    let mut out = HashMap::new();
    for row in rows {
        let get = |i| row.try_get::<_, String>(i).map_err(super::siem::db_error);
        let (id, team, sealed) = (get(0)?, get(1)?, get(2)?);
        let text = super::siem::open_secret(key, &sealed)
            .ok()
            .and_then(|json| serde_json::from_str::<Text>(&json).ok());
        if let Some(text) = text {
            out.insert(id, (team, text));
        }
    }
    Ok(out)
}

/// The text with every secret and every piece of PII Enterplace's detectors find replaced by `[MASKED kind]`. `None`
/// when the detectors cannot run: text that was not checked is never kept.
pub fn redact(text: &Text) -> Option<Text> {
    let guards: Vec<Guardrail> = [Check::Secrets, Check::Pii]
        .into_iter()
        .map(|check| Guardrail {
            name: "export-redaction".into(),
            action: Action::Mask,
            check,
            on: On::REQUEST,
            shadow_until: None,
        })
        .collect();
    let messages: Vec<Value> = text
        .prompt
        .iter()
        .map(|(role, t)| json!({ "role": role, "content": t }))
        .chain(
            text.answer
                .iter()
                .map(|t| json!({ "role": "assistant", "content": t })),
        )
        .collect();
    let verdict = guard::check(json!({ "messages": messages }), &guards);
    if verdict.blocked.is_some() {
        return None;
    }
    let masked: Vec<String> = verdict.body["messages"]
        .as_array()?
        .iter()
        .map(|m| m["content"].as_str().map(str::to_string))
        .collect::<Option<_>>()?;
    let split = text.prompt.len();
    Some(Text {
        prompt: text
            .prompt
            .iter()
            .zip(&masked)
            .map(|((role, _), t)| (role.clone(), t.clone()))
            .collect(),
        answer: masked.get(split..)?.to_vec(),
    })
}
