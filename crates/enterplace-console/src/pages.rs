//! The pages, each built from the markup of its approved screen in design-screens/build.py.

use std::{collections::HashMap, fmt::Write as _, path::Path, time::Instant};

use enterplace_core::{
    config::Loaded,
    id::sha256_hex,
    kill::Kill,
    policy::{Models, Principal, Who},
};
use serde_json::Value;

use crate::{
    Form, Verified,
    figures::{money, time_full, time_list},
    html::{
        Field, button, close_link, code, dialog, document, empty, enc, esc, facts, field, head,
        icon, link, motif, pager, row, shell, tag, thousands, yaml_line,
    },
};

const PER_PAGE: usize = 50;

/// Today's date in UTC, as audit records write it: "2026-11-12".
pub(crate) fn today() -> String {
    date_in(0)
}

/// The date `days` from today, in UTC. Days to a date by Howard Hinnant's civil-from-days.
pub(crate) fn date_in(days: u64) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let z = secs / 86_400 + days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn ago(at: Instant) -> String {
    match at.elapsed().as_secs() {
        0..5 => "just now".into(),
        s @ 5..120 => format!("{s} seconds ago"),
        s @ 120..7200 => format!("{} minutes ago", s / 60),
        s => format!("{} hours ago", s / 3600),
    }
}

fn s<'a>(record: &'a Value, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

/// The paging links of a list: `href(page)` for a page number.
fn pages_of(total: usize, page: usize, noun: &str, href: impl Fn(usize) -> String) -> String {
    let from = (page - 1) * PER_PAGE + 1;
    let to = (page * PER_PAGE).min(total);
    pager(
        &format!(
            "{} to {} of {} {noun}",
            thousands(from),
            thousands(to),
            thousands(total)
        ),
        (&format!("Newer {noun}"), (page > 1).then(|| href(page - 1))),
        (
            &format!("Older {noun}"),
            (to < total).then(|| href(page + 1)),
        ),
    )
}

fn page_number(query: &Form) -> usize {
    query.get("page").parse().unwrap_or(1).max(1)
}

pub(crate) fn tool_page(
    current: &str,
    admin: &str,
    here: &str,
    query: &Form,
    main: &str,
    overlay: &str,
) -> String {
    document(
        current,
        &shell(
            current,
            admin,
            here,
            main,
            overlay,
            query.get("menu") == "1",
        ),
    )
}

// ---------------------------------------------------------------- sign in

/// A flame-edged Banner that is read out when the page opens. `text` is markup.
pub(crate) fn alert(text: &str) -> String {
    format!(
        r#"<div class="g-banner" role="alert" style="border-color: var(--flame)"><span class="t-body">{text}</span></div>"#
    )
}

/// Sign-in has no screen of its own yet, so it is the first-run page (Wizard, WizardKeyFailed) with one field.
/// `key_error` belongs to the key field. `notice` is about sign-in as a whole (single sign-on refused, nothing
/// recorded), so it is a Banner above both ways in and the key field stays at rest.
pub fn sign_in(key_error: &str, notice: &str, sso: bool) -> String {
    sign_in_page(key_error, notice, sso, false)
}

/// The sign-in page just after signing out: it says the sign-out worked.
pub fn signed_out(sso: bool) -> String {
    sign_in_page("", "", sso, true)
}

fn sign_in_page(key_error: &str, notice: &str, sso: bool, out: bool) -> String {
    let key = field(&Field {
        id: "key",
        name: "key",
        label: "Enterplace key",
        value: "",
        mono: true,
        extra: r#" type="password" autocomplete="off" required aria-required="true" autofocus"#,
        hint: "",
        error: key_error,
    });
    let closed = motif(&[""; 12], &["empty"; 6], (4, 2), true, false);
    let notice = if notice.is_empty() {
        String::new()
    } else {
        alert(notice)
    };
    let lead = if sso {
        "Sign in with single sign-on, or paste an admin key."
    } else {
        "Paste your Enterplace key."
    };
    let toast = if out {
        r#"<div class="g-toasts"><div class="g-toast" role="status"><span class="g-toast__text t-body">You signed out.</span></div></div>"#
    } else {
        ""
    };
    let body = format!(
        r#"<div class="g-shell">
<main class="g-shell__main">
<div class="g-split">
<div class="g-stack" style="gap: var(--space-10); padding: var(--space-4)">
<a class="g-nav__brand" href="/console/sign-in" style="padding: 0"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Enterplace</span></a>
<div class="g-stack g-measure">
<h1 class="t-lg" style="margin: 0">Sign in to the console</h1>
<p class="t-lead g-muted" style="margin: 0">{lead}</p>
</div>
{notice}{sso}<form class="g-stack g-measure" style="gap: var(--space-6)" method="post" action="/console/sign-in">
{or_key}{key}
<div class="g-head__actions">{}</div>
</form>
<p class="t-small g-muted g-measure" style="margin: 0">Admin keys only. To make one: <span class="t-mono">enterplace key new &lt;name&gt; --team &lt;team&gt; --admin</span></p>
{other}
</div>
<aside class="g-panel g-stack" style="gap: var(--space-10); padding: var(--space-10); align-content: start">
{closed}
</aside>
</div>
</main>
</div>{toast}"#,
        // With single sign-on on, it is the way in the lead names first; the key form follows as the other way.
        button("Sign in", if sso { "quiet" } else { "" }, "submit", ""),
        sso = if sso {
            format!(
                r#"<div class="g-stack g-measure"><div class="g-head__actions">{}</div></div>
"#,
                link(
                    "Sign in with single sign-on",
                    "",
                    "/console/sso/start",
                    false
                )
            )
        } else {
            String::new()
        },
        or_key = if sso {
            r#"<h2 class="t-md" style="margin: 0">Or paste an admin key</h2>
"#
        } else {
            ""
        },
        // Another way in that the binary embedding the console adds, such as people signing in with a password.
        other = crate::html::EXTRA
            .try_with(|e| e.sign_in.clone())
            .ok()
            .flatten()
            .map_or_else(String::new, |(href, label)| format!(
                r#"<div class="g-head__actions">{}</div>"#,
                link(&esc(&label), "quiet", &esc(&href), false)
            ))
    );
    document("Sign in", &body)
}

/// A page with nothing but one refusal or absence on it: the EmptyState "failed" variant and the way back.
pub fn notice(title: &str, body: &str, href: &str, label: &str) -> String {
    notice_with(title, body, &link(label, "quiet", href, false))
}

/// The Command component: a line to type in a terminal.
fn command(text: &str) -> String {
    format!(
        r#"<span class="g-command"><span class="g-command__text t-mono">{}</span></span>"#,
        esc(text)
    )
}

/// A `enterplace login` link that was cut short or changed. Whoever opened it ran `enterplace login`, so the way out is
/// running it again, not the console's admin sign-in.
pub fn cli_bad_link(message: &str) -> String {
    notice_with(
        "This enterplace login link does not work",
        &esc(message),
        &command("enterplace login"),
    )
}

/// The last page of a `enterplace login`, where the CLI's listener on 127.0.0.1 sends the browser: the key itself goes
/// to the terminal, never to this page, so it only says where to look.
pub fn cli_done(ok: bool) -> String {
    let (title, lead, banner) = if ok {
        (
            "Signed in",
            "Go back to the terminal: enterplace login finishes there and saves your key. You can close this tab.",
            String::new(),
        )
    } else {
        (
            "Not signed in",
            "Go back to the terminal: enterplace login says there why, and what to ask your Enterplace admin.",
            alert("The sign-in was refused, so no key was issued."),
        )
    };
    let body = format!(
        r#"<div class="g-shell">
<main class="g-shell__main">
<div class="g-stack g-measure" style="gap: var(--space-6); padding: var(--space-4)">
<span class="g-nav__brand" style="padding: 0"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Enterplace</span></span>
<h1 class="t-lg" style="margin: 0">{title}</h1>
{banner}<p class="t-lead g-muted" style="margin: 0">{lead}</p>
</div>
</main>
</div>"#
    );
    document(title, &body)
}

/// The EmptyState "failed" page with any action under it.
fn notice_with(title: &str, body: &str, action: &str) -> String {
    let page = format!(
        r#"<div class="g-shell">
<main class="g-shell__main">
<div class="g-stack" style="gap: var(--space-10); padding: var(--space-4)">
<a class="g-nav__brand" href="/console/start" style="padding: 0"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Enterplace</span></a>
{}
</div>
</main>
</div>"#,
        empty(
            &motif(&["", "flame"], &["empty"], (2, 1), true, true),
            title,
            body,
            action,
        )
    );
    document(title, &page)
}

/// Shown for a moment after single sign-on, while the browser opens the console with its new session.
pub fn signed_in_sso() -> String {
    let body = format!(
        r#"<div class="g-shell">
<main class="g-shell__main">
<div class="g-stack g-measure" style="gap: var(--space-6); padding: var(--space-4)">
<a class="g-nav__brand" href="/console/start" style="padding: 0"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Enterplace</span></a>
<h1 class="t-lg" style="margin: 0">Signed in</h1>
<p class="t-lead g-muted" style="margin: 0">Opening the console.</p>
<div class="g-head__actions">{}</div>
</div>
</main>
</div>"#,
        link("Open the console", "", "/console/start", false)
    );
    crate::html::document_with(
        "Signed in",
        r#"<meta http-equiv="refresh" content="0; url=/console/start">"#,
        &body,
    )
}

// ---------------------------------------------------------------- audit log

pub struct AuditView<'a> {
    pub admin: &'a str,
    pub query: &'a Form,
    pub log: &'a Result<Option<String>, String>,
    /// The chain shown: `""` for the install's, else the organization's (`audit: { per_org: true }`).
    pub chain: &'a str,
    /// The chains a person may switch between, as (label, link, shown). Empty with one chain.
    pub chains: &'a [(String, String, bool)],
    pub policy: Option<&'a str>,
    /// The policy as `enterplace check` reads it now, for the budgets and limits a refusal names.
    pub loaded: Option<&'a Loaded>,
    pub verified: Option<Verified>,
    pub read_only: bool,
    /// The kill switches on now, or why they cannot be read.
    pub kills: &'a Result<Vec<Kill>, String>,
    /// The reader may turn a switch off here (`Permission::Kill`).
    pub may_restore: bool,
}

/// What a record sheet reads besides its own record.
struct Context<'a> {
    /// Decisions and changes, oldest first: what came before a record, and who revoked a key.
    records: &'a [Value],
    /// Usage records, oldest first: what a budget had spent when it refused.
    usage: &'a [Value],
    policy: Option<&'a str>,
    loaded: Option<&'a Loaded>,
    /// The record number the last verification found broken.
    broken: Option<u64>,
    /// No action that changes keys is offered.
    read_only: bool,
    kills: &'a [Kill],
}

/// The command that turns a switch off.
pub(crate) fn unkill_command(kill: &Kill) -> String {
    match kill.scope.as_str() {
        "all" => "enterplace unkill --all".into(),
        scope => format!(
            "enterplace unkill --{} {}",
            scope.replace('_', "-"),
            kill.value
        ),
    }
}

/// A command that wraps only between its words: a flag never breaks after its dashes, and a long value still fits a
/// phone.
fn words_whole(text: &str) -> String {
    text.split(' ')
        .map(|w| format!(r#"<span style="white-space: nowrap">{}</span>"#, esc(w)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The banner over the audit log while a kill switch is on: one block per switch, as the KillSwitch design reads,
/// with what it stops, why, since when and by whom, and the command that turns it off.
fn kills_banner(kills: &Result<Vec<Kill>, String>, may_restore: bool) -> String {
    match kills {
        Err(err) => alert(&format!(
            "Every request is refused: the kill switch list cannot be read. {}",
            esc(err)
        )),
        Ok(kills) if kills.is_empty() => String::new(),
        Ok(kills) => {
            // One line per switch, and the button that turns it off. Without the right to, the command an admin runs.
            let lines: String = kills
                .iter()
                .map(|k| {
                    let off = restore(k, may_restore);
                    format!(
                        r#"<div style="display: flex; flex-wrap: wrap; gap: var(--space-4); align-items: center; justify-content: space-between"><span class="t-body">Traffic stopped for <span class="t-mono">{}</span> since {} by {}: {}</span>{off}</div>"#,
                        esc(&k.label()),
                        esc(&time_list(&k.at)),
                        esc(&k.by),
                        esc(&k.reason)
                    )
                })
                .collect();
            format!(
                r#"<div class="g-banner" role="alert" style="border-color: var(--flame)"><div class="g-stack" style="gap: var(--space-3); width: 100%">{lines}</div></div>
"#
            )
        }
    }
}

/// The button that turns switch `k` off. Without the right to, the command an admin runs.
fn restore(k: &Kill, may_restore: bool) -> String {
    if may_restore {
        format!(
            r#"<form method="post" action="/console/kills/restore"><input type="hidden" name="scope" value="{}"><input type="hidden" name="value" value="{}"><button class="g-btn g-btn--sm t-small" type="submit">Restore traffic</button></form>"#,
            esc(&k.scope),
            esc(&k.value)
        )
    } else {
        format!(
            r#"<span class="t-mono-sm">{}</span>"#,
            words_whole(&unkill_command(k))
        )
    }
}

/// Whether switch `k` stops the request of `record`. A record names its key by its first 8 hex characters, a switch
/// by 8 or more, so either may be the longer.
fn kill_stops(k: &Kill, record: &Value) -> bool {
    let key = s(record, "key");
    if k.scope == "key_prefix" {
        return !key.is_empty() && (k.value.starts_with(key) || key.starts_with(&k.value));
    }
    let model = Some(s(record, "model")).filter(|m| !m.is_empty());
    k.stops(s(record, "person"), s(record, "team"), "", model)
}

/// The switches on just before `record`, as the admin records before it in this log set and cleared them.
fn kills_before(record: &Value, records: &[Value]) -> Vec<Kill> {
    let n = record.get("n").and_then(Value::as_u64).unwrap_or(0);
    let mut on: Vec<Kill> = Vec::new();
    for r in records
        .iter()
        .take_while(|r| r.get("n").and_then(Value::as_u64).unwrap_or(0) < n)
        .filter(|r| s(r, "event") == "admin" && s(r, "verdict") == "allow")
    {
        let target = r.get("target").unwrap_or(&Value::Null);
        let (scope, value) = (s(target, "scope"), s(target, "value"));
        match s(r, "action") {
            "set_kill" => {
                let kill = Kill {
                    scope: scope.into(),
                    value: value.into(),
                    reason: s(target, "reason").into(),
                    by: s(r, "person").into(),
                    at: s(r, "time").into(),
                };
                match on.iter_mut().find(|k| k.scope == scope && k.value == value) {
                    Some(old) => *old = kill,
                    None => on.push(kill),
                }
            }
            "clear_kill" => on.retain(|k| !(k.scope == scope && k.value == value)),
            _ => {}
        }
    }
    on
}

/// The sheet of a request a kill switch stopped: the switch as the audit log recorded it then, and whether that same
/// switch is on now. A switch set without a record in this log (an older log file) falls back to one on now that
/// stops such a request.
fn killed_story(record: &Value, ctx: &Context<'_>) -> Story {
    let person = esc(s(record, "person"));
    let whom = if person.is_empty() || person == "unknown" {
        "this request".to_string()
    } else {
        person.clone()
    };
    let none_sent = "Nothing was sent to a provider.";
    let then = kills_before(record, ctx.records)
        .into_iter()
        .find(|k| kill_stops(k, record));
    let Some(kill) = then.or_else(|| ctx.kills.iter().find(|k| kill_stops(k, record)).cloned())
    else {
        return (
            format!("A kill switch stopped {whom}"),
            format!(
                "A kill switch was on for {whom}. It is off now, and this log holds no record of when it was set: an older log file names who set it and why. {none_sent}"
            ),
            vec![("Switch", "Off now".to_string())],
        );
    };
    let still_on = ctx
        .kills
        .iter()
        .any(|k| k.scope == kill.scope && k.value == kill.value);
    let label = esc(&kill.label());
    let by = esc(&kill.by);
    let lead = format!(
        "Kill switch <span class=\"t-mono\">{label}</span> was on: {}. {by} set it at {}. {none_sent} {}",
        esc(kill.reason.trim_end_matches('.')),
        esc(&time_full(&kill.at)),
        if still_on {
            "It is still on: the people it stops see this reason in their tool."
        } else {
            "It is off now, and traffic flows again."
        }
    );
    let state = if still_on {
        tag("block", "Still on", "")
    } else {
        tag("", "Off now", "")
    };
    let mut facts = vec![
        ("Switch", format!("{label} {state}")),
        ("Reason", esc(&kill.reason)),
        ("Set by", format!("{by}, {}", esc(&time_full(&kill.at)))),
    ];
    if still_on {
        facts.push(("Turn off", words_whole(&unkill_command(&kill))));
    }
    (format!("A kill switch stopped {whom}"), lead, facts)
}

/// The filters of the AuditLog design, by their query value.
const SHOW: [(&str, &str); 6] = [
    ("all", "All"),
    ("blocked", "Blocked"),
    ("refused", "Refused"),
    ("masked", "Masked"),
    ("warned", "Warned"),
    ("changes", "Changes"),
];

struct Filter<'a> {
    show: &'a str,
    q: &'a str,
    model: &'a str,
}

/// How a record is opened from the list: by its decision ID, or by its number for a change, which has no ID.
fn rid(record: &Value) -> String {
    match s(record, "id") {
        "" => record
            .get("n")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .to_string(),
        id => id.to_string(),
    }
}

fn findings(record: &Value) -> &[Value] {
    record
        .get("guardrails")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The kind of the first finding a guardrail acted on this way, if any did.
fn found<'a>(record: &'a Value, action: &str) -> Option<&'a str> {
    findings(record)
        .iter()
        .find(|f| s(f, "action") == action)
        .map(|f| s(f, "kind"))
}

/// The verdict of the answer guardrails folded into a request record (`block`, `mask`, `pass`, `not_run`), or "".
fn answer_verdict(record: &Value) -> &str {
    record.get("answer").map_or("", |a| s(a, "verdict"))
}

/// What the answer guardrails found, as the request's own findings are kept.
fn answer_findings(record: &Value) -> &[Value] {
    record
        .get("answer")
        .and_then(|a| a.get("guardrails"))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A request whose answer a guardrail withheld: blocked, though the request itself was allowed.
fn blocked(record: &Value) -> bool {
    s(record, "code") == "guardrail_blocked" || answer_verdict(record) == "block"
}

/// Each `answer_guardrails` record goes onto the request it checked, as `answer`, with its number: the list shows
/// one row per request, and the request's sheet tells what happened to its answer.
fn fold_answers(records: Vec<Value>) -> Vec<Value> {
    let (answers, mut records): (Vec<Value>, Vec<Value>) = records
        .into_iter()
        .partition(|r| s(r, "event") == "answer_guardrails");
    for answer in answers {
        let request = records
            .iter_mut()
            .rev()
            .find(|r| r.get("event").is_none() && s(r, "id") == s(&answer, "id"));
        match request {
            Some(request) => {
                if let Some(map) = request.as_object_mut() {
                    map.insert("answer".into(), answer);
                }
            }
            // Its request is in an older log file: the record stays a row of its own.
            None => records.push(answer),
        }
    }
    records
}

fn is_change(record: &Value) -> bool {
    matches!(
        s(record, "event"),
        "admin" | "config_loaded" | "config_rejected" | "audit_repaired"
    )
}

/// The keys a record names: the target of an issue or a revoke, and the keys a file change added or removed.
fn keys_named(record: &Value) -> Vec<(&str, &str)> {
    fn pair(k: &Value) -> (&str, &str) {
        (s(k, "name"), s(k, "sha256_prefix"))
    }
    let mut out: Vec<(&str, &str)> = record.get("target").map(pair).into_iter().collect();
    for list in ["keys_added", "keys_removed"] {
        if let Some(keys) = record.get(list).and_then(Value::as_array) {
            out.extend(keys.iter().map(pair));
        }
    }
    out
}

impl Filter<'_> {
    fn href(&self, page: usize, record: &str) -> String {
        let mut out = String::from("/console/audit?");
        if !self.show.is_empty() && self.show != "all" {
            let _ = write!(out, "verdict={}&", enc(self.show));
        }
        for (name, value) in [("q", self.q), ("model", self.model), ("record", record)] {
            if !value.is_empty() {
                let _ = write!(out, "{name}={}&", enc(value));
            }
        }
        if page > 1 {
            let _ = write!(out, "page={page}&");
        }
        out.pop();
        out
    }

    fn keeps(&self, record: &Value) -> bool {
        let shown = match self.show {
            "blocked" => blocked(record),
            "refused" => {
                (s(record, "verdict") == "refused" && s(record, "code") != "guardrail_blocked")
                    || s(record, "event") == "config_rejected"
            }
            "masked" => found(record, "mask").is_some() || answer_verdict(record) == "mask",
            "warned" => found(record, "warn").is_some(),
            "changes" => is_change(record),
            _ => true,
        };
        shown && (self.model.is_empty() || s(record, "model") == self.model) && self.matches(record)
    }

    /// Person, team or decision ID; and for a key, its hash prefix or its name, so a revoked key can be traced.
    fn matches(&self, record: &Value) -> bool {
        let q = self.q;
        if q.is_empty()
            || s(record, "person").contains(q)
            || s(record, "team") == q
            || s(record, "id") == q
        {
            return true;
        }
        // A prefix of at least 4 characters either way: the records keep 8, a person may paste all 64.
        let hash = |h: &str| h.len() >= 4 && q.len() >= 4 && (h.starts_with(q) || q.starts_with(h));
        hash(s(record, "key"))
            || keys_named(record)
                .iter()
                .any(|(name, prefix)| (!name.is_empty() && name.contains(q)) || hash(prefix))
    }
}

/// An admin action in words: what was done, and what was tried when it was refused.
fn action_word(action: &str) -> (&str, &str) {
    match action {
        "console_sign_in" => ("signed in", "sign-in"),
        "console_sign_out" => ("signed out", "sign-out"),
        "issue_key" => ("issued a key", "key issue"),
        "revoke_key" => ("revoked a key", "key revoke"),
        "list_keys" => ("listed keys", "key list"),
        "set_kill" => ("stopped traffic", "traffic stop"),
        "clear_kill" => ("restored traffic", "traffic restore"),
        "list_kills" => ("listed switches", "switch list"),
        "start_choice" => ("chose a track", "track choice"),
        "self_issue_key" => ("enterplace login key", "enterplace login"),
        "revoke_own_key" => ("enterplace logout", "enterplace logout"),
        other => (other, other),
    }
}

/// A refusal code in words, as a tag says it: "unknown key", not `unknown_key`.
pub(crate) fn code_words(code: &str) -> String {
    match code {
        "killed" => "kill switch".into(),
        other => other.replace('_', " "),
    }
}

/// The FindingBadge of one guardrail finding.
fn badge(action: &str, kind: &str) -> String {
    let (class, word) = match action {
        "block" => ("block", "Block"),
        "mask" => ("mask", "Mask"),
        "warn" => ("warn", "Warn"),
        _ => ("", "Found"),
    };
    tag(class, word, kind)
}

fn verdict(record: &Value) -> String {
    match s(record, "event") {
        "admin" => {
            let (done, tried) = action_word(s(record, "action"));
            return if s(record, "verdict") == "allow" {
                tag("", "Admin:", done)
            } else {
                tag("refused", "Refused:", tried)
            };
        }
        "config_loaded" => return tag("", "Change", "policy loaded"),
        "config_rejected" => return tag("refused", "Refused", "policy change"),
        "audit_repaired" => return tag("", "Change", "log repaired"),
        _ => {}
    }
    let answer_kind = |action: &str| {
        answer_findings(record)
            .iter()
            .find(|f| s(f, "action") == action)
            .map_or("answer", |f| s(f, "kind"))
    };
    match answer_verdict(record) {
        "block" => return badge("block", answer_kind("block")),
        "mask" => return badge("mask", answer_kind("mask")),
        _ => {}
    }
    match (s(record, "verdict"), s(record, "code")) {
        (_, "guardrail_blocked") => badge("block", found(record, "block").unwrap_or("guardrail")),
        ("refused", code) => tag("refused", "Refused:", &code_words(code)),
        ("allow", _) => match (found(record, "mask"), found(record, "warn")) {
            (Some(kind), _) => badge("mask", kind),
            (None, Some(kind)) => badge("warn", kind),
            (None, None) => tag("allow", "Allowed", ""),
        },
        _ => tag("", "Change", s(record, "event")),
    }
}

/// Who a record is about, for the list: a change to the files was made by no one Enterplace knows, so it says how.
fn who(record: &Value) -> String {
    match s(record, "event") {
        "config_loaded" | "config_rejected" => trigger_word(s(record, "trigger")).to_string(),
        "audit_repaired" => "enterplace audit repair".to_string(),
        _ => s(record, "person").to_string(),
    }
}

fn trigger_word(trigger: &str) -> &str {
    match trigger {
        "start" => "Enterplace start",
        "file_change" => "file change",
        "signal" => "reload signal",
        other => other,
    }
}

fn audit_table(rows: &[&Value], selected: &str, filter: &Filter<'_>, page: usize) -> String {
    let mut body = String::new();
    for record in rows {
        let id = rid(record);
        let sel = if id == selected && id != "0" {
            r#" aria-selected="true""#
        } else {
            ""
        };
        let sub = match (s(record, "team"), s(record, "key")) {
            ("", "") => String::new(),
            ("", key) => format!("key hash {key}"),
            (team, _) => team.to_string(),
        };
        let _ = writeln!(
            body,
            r#"<tr{sel}><td>{}<span class="g-table__sub">{}</span></td><td>{}</td><td>{}</td><td class="g-table__wide">{}</td></tr>"#,
            ident(&who(record)),
            esc(&sub),
            verdict(record),
            open_link(record, &id, filter, page),
            esc(s(record, "model")),
        );
    }
    format!(
        "<div class=\"g-table-wrap\"><table class=\"g-table g-table--stack t-mono-sm\" data-rows-open>\n<thead class=\"t-tag\"><tr><th>Person or workload</th><th>Verdict</th><th>Time</th><th>Model</th></tr></thead>\n<tbody>\n{body}</tbody>\n</table></div>"
    )
}

/// The row's link to its sheet, on its time: the ID is in the sheet, a 26-character ID is no label for a row.
fn open_link(record: &Value, id: &str, filter: &Filter<'_>, page: usize) -> String {
    // An admin action has a decision ID; a change to the files has only its record number.
    let label = if s(record, "id").is_empty() {
        format!("Open record {id}")
    } else {
        format!("Open decision {id}")
    };
    format!(
        r#"<a href="{}" aria-label="{}">{}</a>"#,
        filter.href(page, id),
        esc(&label),
        esc(&time_list(s(record, "time")))
    )
}

/// A name for a list cell. Identifiers are never broken mid-word; only an email may break, after its @ and dots.
fn ident(name: &str) -> String {
    if name.contains('@') {
        esc(name).replace('@', "@<wbr>").replace('.', ".<wbr>")
    } else {
        esc(name)
    }
}

/// The Changes view, as the AuditChanges screen lays it out: who, what changed and why, and when.
fn changes_table(
    rows: &[&Value],
    selected: &str,
    filter: &Filter<'_>,
    page: usize,
    ctx: &Context<'_>,
) -> String {
    let mut body = String::new();
    for record in rows {
        let id = rid(record);
        let sel = if id == selected {
            r#" aria-selected="true""#
        } else {
            ""
        };
        let (title, _, _) = story(record, ctx);
        let _ = writeln!(
            body,
            r#"<tr{sel}><td>{}</td><td><span class="t-body">{title}</span><span class="g-table__sub">{}</span></td><td>{}</td></tr>"#,
            ident(&who(record)),
            verdict(record),
            open_link(record, &id, filter, page),
        );
    }
    format!(
        "<div class=\"g-table-wrap\"><table class=\"g-table g-table--stack g-table--prose t-mono-sm\" data-rows-open>\n<thead class=\"t-tag\"><tr><th>Who</th><th>Change and reason</th><th>Time</th></tr></thead>\n<tbody>\n{body}</tbody>\n</table></div>"
    )
}

/// A finding kind in words, for a sentence: "an AWS access key".
fn kind_words(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "aws_access_key" => "an AWS access key",
        "private_key" => "a private key",
        "github_token" => "a GitHub token",
        "slack_token" => "a Slack token",
        "enterplace_key" => "a Enterplace key",
        "jwt" => "a signed token (JWT)",
        "api_key" => "an API key",
        "email_address" => "an email address",
        "iban" => "a bank account number (IBAN)",
        "credit_card" => "a credit card number",
        "us_ssn" => "a US social security number",
        "israeli_id" => "an Israeli ID number",
        "phone_number" => "a phone number",
        _ => return None,
    })
}

/// Kinds that are credentials: one that reached Enterplace should be rotated.
const SECRETS: [&str; 7] = [
    "aws_access_key",
    "private_key",
    "github_token",
    "slack_token",
    "enterplace_key",
    "jwt",
    "api_key",
];

/// "1 December", the day after a period that ends with the date of `time`.
fn reset_day(time: &str, per_day: bool) -> String {
    let part = |range: std::ops::Range<usize>| {
        time.get(range)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(1)
    };
    let (year, month, day) = (part(0..4), part(5..7).clamp(1, 12), part(8..10));
    let (month, day) = if per_day && (day as usize) < days_in(year, month) {
        (month, day + 1)
    } else {
        (month % 12 + 1, 1)
    };
    format!("{day} {}", MONTHS[month as usize - 1])
}

/// Title, lead and facts of a budget or rate refusal, from the rule that refused it. `None` when the policy has
/// changed since: the amounts of another version would be wrong.
fn limit_story(record: &Value, ctx: &Context<'_>) -> Option<Story> {
    let loaded = ctx
        .loaded
        .filter(|l| l.policy_sha256 == s(record, "policy_sha256"))?;
    let rule = loaded
        .policy
        .rule_list()
        .iter()
        .find(|r| r.name == s(record, "rule"))?;
    let (person, rule_name) = (esc(s(record, "person")), esc(&rule.name));
    let none_sent = "Nothing was sent to a provider.";
    if s(record, "code") == "rate_limited" {
        return rate_story(record, ctx, rule);
    }
    let budget = rule.limits.budget()?;
    let per_day = budget.per == enterplace_core::policy::Period::Day;
    let time = s(record, "time");
    // A team rule counts the team's spend; a name or `any` rule counts the person's.
    let (whose, field, value) = match &rule.who {
        Who::Team(team) => (format!("The {} team", esc(team)), "team", team.as_str()),
        _ => (person.clone(), "person", s(record, "person")),
    };
    let spent = spent_before(ctx.usage, time, per_day, |u| s(u, field) == value);
    let (per, reset) = (budget.per.word(), reset_day(time, per_day));
    let summary = format!("{} of {} spent this {per}", money(spent), money(budget.usd));
    Some((
        format!("{whose}'s budget is spent"),
        format!(
            "{summary}, plus what requests in flight held, and this request could have cost more than the rest of the {} that rule {rule_name} at line {} allows. Refused until {reset}. {none_sent}",
            money(budget.usd),
            rule.line
        ),
        vec![
            ("Budget", summary),
            ("Resets", format!("{reset}, 00:00 UTC")),
        ],
    ))
}

/// A rate refusal: requests a minute, tokens a minute of the rule, or tokens a minute of the key. The record does not
/// say which one refused, so with more than one in force the sheet names them all.
fn rate_story(
    record: &Value,
    ctx: &Context<'_>,
    rule: &enterplace_core::policy::Rule,
) -> Option<Story> {
    let (person, rule_name, line) = (esc(s(record, "person")), esc(&rule.name), rule.line);
    let none_sent = "Nothing was sent to a provider.";
    let whose = match &rule.who {
        Who::Team(team) => format!("the {} team", esc(team)),
        _ => person.clone(),
    };
    let key = esc(s(record, "key"));
    let mut limits: Vec<(&'static str, String)> = Vec::new();
    if let Some(rpm) = rule.limits.rpm {
        limits.push((
            "Limit",
            format!("{} requests a minute", thousands(rpm as usize)),
        ));
    }
    if let Some(tpm) = rule.limits.tpm {
        limits.push((
            "Limit",
            format!("{} tokens a minute", thousands(tpm as usize)),
        ));
    }
    if let Some(tpm) = key_of(record, ctx).and_then(|p| p.tpm) {
        limits.push((
            "Key limit",
            format!("{} tokens a minute", thousands(tpm as usize)),
        ));
    }
    // A record that names the limit that refused it (`limit: { kind, of, value }`) keeps only that one.
    if let Some(limit) = record.get("limit") {
        let word = match s(limit, "kind") {
            "rpm" => "requests a minute",
            _ => "tokens a minute",
        };
        let label = if s(limit, "of") == "key" {
            "Key limit"
        } else {
            "Limit"
        };
        let value = limit.get("value").and_then(Value::as_u64).unwrap_or(0);
        let named = format!("{} {word}", thousands(usize::try_from(value).unwrap_or(0)));
        limits.retain(|(l, text)| *l == label && *text == named);
        if limits.is_empty() {
            limits.push((label, named));
        }
    }
    // A request larger than the whole minute's limit could never pass: it was given no time to send again.
    if let Some(limit) = record.get("limit").filter(|l| s(l, "kind") == "tpm") {
        let (value, could) = (
            limit.get("value").and_then(Value::as_u64).unwrap_or(0),
            limit
                .get("request_could_use")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        if could > value {
            let (who, label) = if s(limit, "of") == "key" {
                (format!("{person}'s key"), "Key limit")
            } else {
                (whose.clone(), "Limit")
            };
            let n = |v: u64| thousands(usize::try_from(v).unwrap_or(usize::MAX));
            return Some((
                format!("This request alone is larger than {who} allows in a minute"),
                format!(
                    "This request could use {} tokens (the prompt and the most the answer may write), more than the {} {who} allows in a minute, so it could never pass and no retry time was given. Send a shorter request or a smaller max_tokens. {none_sent}",
                    n(could),
                    n(value)
                ),
                vec![
                    (label, format!("{} tokens a minute", n(value))),
                    ("Request", format!("{} tokens", n(could))),
                ],
            ));
        }
    }
    let tokens = "Tokens count the prompt and the most the answer may write. The client was told when to send again.";
    let only = |label: &str, word: &str| {
        limits.len() == 1 && limits[0].0 == label && limits[0].1.ends_with(word)
    };
    match (
        only("Limit", "requests a minute"),
        only("Limit", "tokens a minute"),
        limits.len(),
    ) {
        (_, _, 0) => None,
        (true, _, _) => Some((
            format!("{person} sent too many requests"),
            format!(
                "Rule {rule_name} at line {line} allows {} for each person, and {person} had sent them all in the last minute. The client was told when to send again. {none_sent}",
                limits[0].1
            ),
            limits,
        )),
        (_, true, _) => Some((
            format!("{} used up its tokens for the minute", capital(&whose)),
            format!(
                "Rule {rule_name} at line {line} allows {} for {whose}, and this request would have gone past it. {tokens} {none_sent}",
                limits[0].1
            ),
            limits,
        )),
        (_, _, 1) => Some((
            format!("{person}'s key used up its tokens for the minute"),
            format!(
                "The keys file allows key {key} {}, and this request would have gone past it. {tokens} {none_sent}",
                limits[0].1
            ),
            limits,
        )),
        _ => Some((
            format!("{person} passed a rate limit"),
            format!(
                "Rule {rule_name} at line {line} and the keys file set the limits below. One of them refused this request; the record does not say which. {tokens} {none_sent}"
            ),
            limits,
        )),
    }
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

type Story = (String, String, Vec<(&'static str, String)>);

/// What usage records that `mine` keeps had charged in the period (day or month) of `time`, up to `time`.
fn spent_before(usage: &[Value], time: &str, per_day: bool, mine: impl Fn(&Value) -> bool) -> f64 {
    let period = time.get(..if per_day { 10 } else { 7 }).unwrap_or("");
    usage
        .iter()
        .filter(|u| s(u, "time").starts_with(period) && s(u, "time") <= time && mine(u))
        .filter_map(|u| u.get("charged_usd").and_then(Value::as_f64))
        .sum()
}

/// "1 November 2020" for a date or time the keys file or a record writes, or `short`: "1 Nov".
pub(crate) fn day_words(date: &str, short: bool) -> String {
    let part =
        |range: std::ops::Range<usize>| date.get(range).and_then(|p| p.parse::<usize>().ok());
    match (part(0..4), part(5..7), part(8..10)) {
        (Some(_), Some(month @ 1..=12), Some(day)) if short => {
            format!("{day} {}", MONTHS[month - 1].get(..3).unwrap_or(""))
        }
        (Some(year), Some(month @ 1..=12), Some(day)) => {
            format!("{day} {} {year}", MONTHS[month - 1])
        }
        _ => date.to_string(),
    }
}

/// The key a record was sent with, as the keys file that decided it gave it. `None` when the file has changed since,
/// so an expiry or a budget shown would be another version's.
fn key_of<'a>(record: &Value, ctx: &Context<'a>) -> Option<&'a Principal> {
    let key = s(record, "key");
    ctx.loaded
        .filter(|l| !key.is_empty() && l.keys_sha256 == s(record, "keys_sha256"))?
        .policy
        .entries()
        .map(|(_, p)| p)
        .find(|p| p.key == key)
}

/// The sheet of a refusal by the key's own expiry or budget, from the keys file.
fn key_story(record: &Value, ctx: &Context<'_>) -> Story {
    let (person, key) = (esc(s(record, "person")), esc(s(record, "key")));
    let none_sent = "Nothing was sent to a provider.";
    let entry = key_of(record, ctx);
    if s(record, "code") == "key_expired" {
        return match entry.and_then(|p| p.expires.as_deref()) {
            Some(at) => (
                format!("{person}'s key expired on {}", day_words(at, false)),
                format!(
                    "The keys file gives key {key} an expiry of {} (UTC), and Enterplace refuses it from then on. {none_sent} Issue {person} a new key on People, then revoke this one.",
                    esc(at)
                ),
                vec![("Expired", esc(at))],
            ),
            None => (
                format!("{person}'s key had expired"),
                format!(
                    "Key {key} was past the expiry the keys file gave it. The keys file has changed since, so the date is not shown here. {none_sent}"
                ),
                Vec::new(),
            ),
        };
    }
    let Some(budget) = entry.and_then(|p| p.budget) else {
        return (
            format!("{person}'s key budget is spent"),
            format!(
                "The budget the keys file gives key {key} did not cover this request. The keys file has changed since, so its amounts are not shown here. {none_sent}"
            ),
            Vec::new(),
        );
    };
    let per_day = budget.per == enterplace_core::policy::Period::Day;
    let time = s(record, "time");
    let spent = spent_before(ctx.usage, time, per_day, |u| {
        s(u, "key") == s(record, "key")
    });
    let reset = reset_day(time, per_day);
    let summary = format!(
        "{} of {} spent {}",
        money(spent),
        money(budget.usd),
        if per_day { "today" } else { "this month" }
    );
    let until = if per_day {
        "00:00 UTC".to_string()
    } else {
        reset.clone()
    };
    (
        format!("{person}'s key budget is spent"),
        format!(
            "{summary}, plus what requests in flight held, and this request could have cost more than the rest of the {} the keys file gives key {key}. Refused until {until}. {none_sent}",
            money(budget.usd)
        ),
        vec![
            ("Budget", summary),
            ("Resets", format!("{reset}, 00:00 UTC")),
        ],
    )
}

/// What a record says happened, in a sentence, what follows from it, and facts only this kind of record has.
/// Every part is markup.
fn story(record: &Value, ctx: &Context<'_>) -> Story {
    let (person, team, model) = (
        esc(s(record, "person")),
        esc(s(record, "team")),
        esc(s(record, "model")),
    );
    let (rule, line) = (
        esc(s(record, "rule")),
        record.get("rule_line").and_then(Value::as_u64).unwrap_or(0),
    );
    let none_sent = "Nothing was sent to a provider.";
    match s(record, "event") {
        "admin" => return admin_story(record),
        "config_loaded" | "config_rejected" => return change_story(record),
        "audit_repaired" => return repair_story(record),
        _ => {}
    }
    let plain = |title: &str, lead: String| (title.to_string(), lead, Vec::new());
    match (s(record, "verdict"), s(record, "code")) {
        ("allow", _) => {
            let masked: u64 = findings(record)
                .iter()
                .filter(|f| s(f, "action") == "mask")
                .filter_map(|f| f.get("count").and_then(Value::as_u64))
                .sum();
            let provider = esc(s(record, "provider"));
            let answer = answer_findings(record);
            let acted = |action: &str| -> Vec<&Value> {
                answer.iter().filter(|f| s(f, "action") == action).collect()
            };
            let kinds = |list: &[&Value]| {
                list.iter()
                    .map(|f| {
                        format!(
                            "{} ({})",
                            esc(s(f, "kind")),
                            f.get("count").and_then(Value::as_u64).unwrap_or(0)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            match answer_verdict(record) {
                "block" => {
                    let found = acted("block");
                    let guardrail = found.first().map_or("", |f| s(f, "guardrail"));
                    return plain(
                        &format!(
                            r#"Guardrail <span style="white-space: nowrap">{}</span> withheld the answer"#,
                            esc(guardrail)
                        ),
                        format!(
                            "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it, and it was sent to {provider}. The model answered; the answer contained {} and the caller got guardrail_blocked instead. Usage still counts it.",
                            kinds(&found)
                        ),
                    );
                }
                "mask" => {
                    let found = acted("mask");
                    return plain(
                        &format!("Sent to {provider}, and the answer was masked"),
                        format!(
                            "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it, and it was sent to {provider}. Its guardrails replaced {} in the answer before it reached the caller. The findings below give each kind, never the text.",
                            kinds(&found)
                        ),
                    );
                }
                _ => {}
            }
            if masked > 0 {
                let n = enterplace_core::count(usize::try_from(masked).unwrap_or(0), "finding");
                return plain(
                    &format!("Masked {n}, then sent to {provider}"),
                    format!(
                        "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it. Its guardrails replaced {n} in the request before it was sent to {provider}. The findings below give each kind, never the text."
                    ),
                );
            }
            plain(
                "Allowed and sent to the provider",
                format!(
                    "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it, and it was sent to {provider}."
                ),
            )
        }
        (_, "no_key") => plain(
            "The request carried no Enterplace key",
            format!("Enterplace refuses a request it cannot put a name on. {none_sent}"),
        ),
        (_, "unknown_key") => {
            let key = s(record, "key");
            // The revoke of this key, if it is in this log: who still uses it is the question, who revoked it the start.
            let revoked = ctx.records.iter().find(|r| {
                s(r, "action") == "revoke_key"
                    && s(r, "verdict") == "allow"
                    && !key.is_empty()
                    && r.get("target").map(|t| s(t, "sha256_prefix")) == Some(key)
            });
            let mut out = plain(
                "The request carried a key Enterplace did not issue",
                format!(
                    "The hash of the key starts with {}. {none_sent} If it is a revoked key, someone still uses it.",
                    esc(key)
                ),
            );
            if let Some(r) = revoked {
                out.2.push((
                    "Revoked",
                    format!(
                        r#"Revoked by {} at {}, <a href="/console/audit?record={}">record {}</a>"#,
                        esc(s(r, "person")),
                        esc(&time_full(s(r, "time"))),
                        enc(&rid(r)),
                        r.get("n").and_then(Value::as_u64).unwrap_or(0)
                    ),
                ));
            }
            out
        }
        (_, "no_rule") => plain(
            "No rule names this person",
            format!(
                "Anything the policy does not allow is refused. {none_sent} Add a rule for {person} or team {team} to allow it."
            ),
        ),
        (_, "model_not_allowed") => {
            let rule_allows = ctx
                .loaded
                .filter(|l| l.policy_sha256 == s(record, "policy_sha256"))
                .and_then(|l| {
                    l.policy
                        .rule_list()
                        .iter()
                        .find(|r| r.name == s(record, "rule"))
                })
                .map(|r| r.allows(s(record, "model")));
            let key_models = key_of(record, ctx).and_then(|p| p.models.as_ref());
            // A record that says a key's own list refused it is believed first.
            let by_key = record.get("key_models") == Some(&Value::Bool(true))
                || rule_allows == Some(true)
                || (rule_allows.is_none()
                    && key_models.is_some_and(|m| !m.iter().any(|x| x == s(record, "model"))));
            if !by_key && rule_allows.is_none() {
                return plain(
                    "This model was not allowed for this person",
                    format!(
                        "The policy has changed since this decision, and the record does not say whether rule {rule} or the key's own models refused {model}. {none_sent}"
                    ),
                );
            }
            if !by_key {
                return plain(
                    "This model is not allowed for this person",
                    format!(
                        "Rule {rule} at line {line} decides for {person} and does not list {model}. {none_sent}"
                    ),
                );
            }
            let list = key_models.map(|m| esc(&m.join(", ")));
            (
                format!("{person}'s key does not allow {model}"),
                format!(
                    "Rule {rule} at line {line} {} for {person}, but the keys file gives key {} its own list of models{}. {none_sent} Add {model} to the key's models in the keys file if {person} needs it.",
                    if rule_allows == Some(true) {
                        format!("allows {model}")
                    } else {
                        "decides".to_string()
                    },
                    esc(s(record, "key")),
                    list.as_ref().map_or(String::new(), |l| format!(": {l}"))
                ),
                list.map(|l| vec![("Key models", l)]).unwrap_or_default(),
            )
        }
        (_, "guardrail_blocked") => {
            let block = findings(record).iter().find(|f| s(f, "action") == "block");
            let kind = block.map_or("", |f| s(f, "kind"));
            // A vendor's category (moderation's harassment_threatening) has no words of ours: it reads as it is.
            let title = match (kind_words(kind), block) {
                (Some(words), _) => format!("The prompt held {words}"),
                (None, Some(f)) if !kind.is_empty() => format!(
                    "Guardrail {} blocked {}",
                    esc(s(f, "guardrail")),
                    esc(&kind.replace('_', " "))
                ),
                _ => "A guardrail blocked this request".to_string(),
            };
            let by = block.map_or(String::new(), |f| {
                format!(" Guardrail {} stops it.", esc(s(f, "guardrail")))
            });
            let rotate = if SECRETS.contains(&kind) {
                " If it is real, it should be rotated."
            } else {
                ""
            };
            plain(
                &title,
                format!(
                    "Rule {rule} at line {line} allows {model} for {person}.{by} The request went no further: {} The prompt was not stored, and the findings below give each kind, never the text.{rotate}",
                    none_sent.to_lowercase()
                ),
            )
        }
        (_, "budget_exceeded" | "rate_limited") => limit_story(record, ctx).unwrap_or_else(|| {
            let what = if s(record, "code") == "rate_limited" {
                "rate limit"
            } else {
                "budget"
            };
            plain(
                &format!("Refused by the {what} of rule {rule}"),
                format!(
                    "Rule {rule} at line {line} sets a {what}, and this request would have passed it. The policy has changed since, so its amounts are not shown here. {none_sent}"
                ),
            )
        }),
        (_, "key_budget_exceeded" | "key_expired") => key_story(record, ctx),
        (_, "killed") => killed_story(record, ctx),
        (_, "max_tokens_needed") => {
            let field = match s(record, "path") {
                "/v1/responses" => "max_output_tokens",
                "/v1/messages" => "max_tokens",
                _ => "max_tokens (or max_completion_tokens)",
            };
            plain(
                "A budget applies, and the request set no output limit",
                format!(
                    "A budget applies to {person}'s request for {model}, and it did not say how many output tokens it may use, so the most it could cost was unknown. {none_sent} The client sends {field} with the request, or an admin sets max_output for {model} under prices: in the policy."
                ),
            )
        }
        (_, "bad_limits") => plain(
            "The request's limits could not be read",
            format!(
                "A budget or a cache applies to {person}'s request, so Enterplace reads the model, the messages and the token limits to know what it could cost. One of them was sent twice, or a token limit was not a whole number. {none_sent} The client sends each field at most once, token limits as whole numbers."
            ),
        ),
        (_, "wrong_route") => plain(
            "This model is not served on this route",
            format!(
                "{person} sent {model} to {}, and the provider that serves {model} does not take that route through Enterplace. {none_sent} The error the client got names the route to send it to.",
                esc(s(record, "path"))
            ),
        ),
        (_, "unreadable_request") => plain(
            "Enterplace could not read the request",
            format!(
                "The body was cut short, compressed, or not a JSON object with one model field, so the policy could not be checked. {none_sent} The client sends the request again as plain JSON."
            ),
        ),
        (_, "unknown_model") => plain(
            "No provider serves this model",
            format!("No provider in the policy lists {model}. {none_sent}"),
        ),
        ("refused", code) => plain(
            "Refused",
            format!("Enterplace refused it with the code {}. {none_sent}", esc(code)),
        ),
        _ => plain(
            "A record in the chain",
            format!(
                "Recorded in the chain between the requests, as {}.",
                esc(s(record, "event"))
            ),
        ),
    }
}

fn admin_story(record: &Value) -> Story {
    let target = record.get("target").unwrap_or(&Value::Null);
    let name = esc(s(target, "name"));
    let hash = match s(target, "sha256_prefix") {
        "" => String::new(),
        prefix => format!(", key hash {}", esc(prefix)),
    };
    let admin_key = target.get("admin") == Some(&Value::Bool(true));
    let (did, tried) = match s(record, "action") {
        "console_sign_in" => (
            "signed in to the console".to_string(),
            "sign in to the console".to_string(),
        ),
        "console_sign_out" => ("signed out of the console".into(), "sign out".into()),
        "issue_key" if admin_key => (
            format!("issued an admin key for {name}{hash}"),
            format!("issue an admin key for {name}"),
        ),
        "issue_key" => (
            format!("issued a key for {name}{hash}"),
            format!("issue a key for {name}"),
        ),
        "revoke_key" => (
            format!("revoked the key of {name}{hash}"),
            format!("revoke the key of {name}{hash}"),
        ),
        "list_keys" => ("listed the keys".into(), "list the keys".into()),
        "revoke_own_key" => (
            format!("gave up their own key with enterplace logout{hash}"),
            format!("give up their own key{hash}"),
        ),
        "self_issue_key" => (
            format!("got a personal key with enterplace login{hash}"),
            "get a personal key with enterplace login".to_string(),
        ),
        "list_kills" => (
            "listed the kill switches".into(),
            "list the kill switches".into(),
        ),
        "set_kill" | "clear_kill" => {
            let what = match (s(target, "scope"), s(target, "value")) {
                ("all", _) => "everyone".to_string(),
                ("key_prefix", v) => format!("key {}", esc(v)),
                (scope, v) => format!("{} {}", esc(scope), esc(v)),
            };
            if s(record, "action") == "set_kill" {
                (
                    format!("stopped traffic for {what}"),
                    format!("stop traffic for {what}"),
                )
            } else {
                (
                    format!("let traffic flow again for {what}"),
                    format!("let traffic flow again for {what}"),
                )
            }
        }
        other => (esc(other), esc(other)),
    };
    let who = match s(record, "person") {
        "" | "unknown" => "Someone".to_string(),
        person => esc(person),
    };
    let reason = match s(target, "reason").trim_end_matches('.') {
        "" => String::new(),
        reason => format!(": {}", esc(reason)),
    };
    // The title names the act without the hash, which the lead and the facts carry.
    let act = did.strip_suffix(hash.as_str()).unwrap_or(&did);
    // A key that ends: an issued one with an expiry, or one from enterplace login, which always has one.
    let expires = match s(target, "expires") {
        "" => Vec::new(),
        at => vec![("Expires", esc(&day_words(at, false)))],
    };
    match s(record, "verdict") {
        "allow" => (
            format!("{who} {act}"),
            format!("{who} {did}{reason}."),
            expires,
        ),
        "failed" => (
            format!("{who} {act}, and it failed"),
            format!(
                "{who} {did}. It was allowed and then failed, so nothing changed: {}",
                esc(s(record, "error"))
            ),
            Vec::new(),
        ),
        _ => (
            format!(
                "{who} was refused: {}",
                tried.strip_suffix(hash.as_str()).unwrap_or(&tried)
            ),
            format!(
                "{who} tried to {tried}. It was refused with the code {}{reason}. Nothing changed.",
                esc(s(record, "code"))
            ),
            Vec::new(),
        ),
    }
}

fn change_story(record: &Value) -> Story {
    let trigger = s(record, "trigger");
    let mut facts = vec![("Trigger", esc(trigger_word(trigger)))];
    for (label, key) in [
        ("Policy before", "policy_sha256_before"),
        ("Keys before", "keys_sha256_before"),
    ] {
        facts.push((label, esc(s(record, key))));
    }
    if s(record, "event") == "config_rejected" {
        let problems: Vec<&str> = record
            .get("problems")
            .and_then(Value::as_array)
            .map(|p| p.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        facts.extend(problems.iter().map(|p| ("Problem", esc(p))));
        return (
            "A change to the policy or keys file was rejected".into(),
            format!(
                "Enterplace kept deciding with the version it had loaded. The change has {}, listed below: fix them and save again. <span class=\"t-mono\">enterplace check</span> names the same.",
                enterplace_core::count(problems.len(), "problem")
            ),
            facts,
        );
    }
    let mut changed = (0, 0);
    for (label, list, n) in [
        ("Key added", "keys_added", &mut changed.0),
        ("Key removed", "keys_removed", &mut changed.1),
    ] {
        for key in record
            .get(list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            *n += 1;
            facts.push((
                label,
                esc(&format!(
                    "{}, {}, key hash {}",
                    s(key, "name"),
                    s(key, "team"),
                    s(key, "sha256_prefix")
                )),
            ));
        }
    }
    let when = match trigger {
        "start" => "as it started",
        "file_change" => "after one of them changed",
        "signal" => "on a reload signal",
        _ => "",
    };
    let keys = match changed {
        (0, 0) => "No key was added or removed.".to_string(),
        (a, r) => format!(
            "{} added and {} removed.",
            enterplace_core::count(a, "key"),
            r
        ),
    };
    // The title names what changed: the files' hashes before and after say which, the keys lists say how.
    let differs = |key: &str| {
        let before = s(record, &format!("{key}_before"));
        !before.is_empty() && before != s(record, key)
    };
    let named: Vec<String> = [("keys_added", "added"), ("keys_removed", "removed")]
        .iter()
        .flat_map(|(list, word)| {
            record
                .get(*list)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(move |k| format!("{} {word}", esc(s(k, "name"))))
        })
        .collect();
    let title = match (trigger, differs("policy_sha256"), differs("keys_sha256")) {
        ("start", _, _) => "Enterplace started with this policy and keys".to_string(),
        (_, true, true) => "The policy and keys files changed".to_string(),
        (_, true, false) => "The policy file changed".to_string(),
        (_, false, true) if !named.is_empty() => {
            format!("The keys file changed: {}", named.join(", "))
        }
        (_, false, true) => "The keys file changed".to_string(),
        _ => "The policy and keys files were loaded again".to_string(),
    };
    (
        title,
        format!(
            "Enterplace loaded the policy and keys files {when}. {keys} Requests after this record are decided by this version."
        ),
        facts,
    )
}

/// A cut last line removed by `enterplace audit repair`: what was removed is in the record, so nothing is lost silently.
fn repair_story(record: &Value) -> Story {
    let bytes = record
        .get("removed_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (
        "The cut last line of the audit log was removed".into(),
        format!(
            "The log ended with a line that was cut short as it was written, so it could not be checked. <span class=\"t-mono\">enterplace audit repair</span> removed its {bytes} bytes and wrote this record, which holds them, while Enterplace was stopped. Every record before it still holds."
        ),
        vec![
            ("Removed", format!("{bytes} bytes")),
            ("Removed hash", esc(s(record, "removed_sha256"))),
            ("Removed text", esc(s(record, "removed_text"))),
        ],
    )
}

/// The lines that differ between two versions of the policy, with one line around each change.
// ponytail: a longest-common-subsequence table, lines squared. Policy files are a few hundred lines at most.
pub(crate) fn diff(old: &str, new: &str) -> Vec<(usize, String, &'static str)> {
    enterplace_core::versions::diff(old, new)
        .into_iter()
        .map(|(n, line, kind)| (n, yaml_line(&line), kind))
        .collect()
}

/// The policy text a change loaded, against the one loaded before it in this log.
fn change_snippet(record: &Value, ctx: &Context<'_>) -> String {
    let n = record.get("n").and_then(Value::as_u64).unwrap_or(0);
    let before =
        ctx.records.iter().rev().find(|r| {
            s(r, "event") == "config_loaded" && r.get("n").and_then(Value::as_u64) < Some(n)
        });
    let note = |text: &str| format!(r#"<p class="t-small g-muted" style="margin: 0">{text}</p>"#);
    match (before.map(|r| s(r, "policy")), s(record, "policy")) {
        (_, "") => String::new(),
        (None, _) => {
            note("The first version of the policy in this log. The record holds its whole text.")
        }
        (Some(old), new) if old == new => {
            note("The policy text did not change: only the keys file did.")
        }
        (Some(old), new) => {
            note("What changed in the policy file, against the version loaded before it.")
                + &code(&diff(old, new))
        }
    }
}

fn missing_sheet(selected: &str, close: &str) -> String {
    format!(
        r#"<div class="g-scrim g-scrim--sheet">
<aside class="g-sheet" role="dialog" aria-modal="true" aria-labelledby="record-title">
<div class="g-pager"><span></span><a class="g-btn g-btn--quiet g-btn--icon" href="{close}" aria-label="Close" data-close>{}</a></div>
<div class="g-stack">
<h2 class="t-md" id="record-title" style="margin: 0">No record has this ID</h2>
<p class="t-body g-muted" style="margin: 0">No record in this audit log has decision ID or number <span class="t-mono">{}</span>. It may be in an older log file, or the ID was cut short when it was copied.</p>
</div>
</aside>
</div>"#,
        icon("close"),
        esc(selected)
    )
}

fn record_sheet(record: &Value, ctx: &Context<'_>, close: &str) -> String {
    let (title, lead, extra) = story(record, ctx);
    let id = s(record, "id");
    let both = |a: &str, b: &str| match (a, b) {
        ("", b) => b.to_string(),
        (a, "") => a.to_string(),
        (a, b) => format!("{a}, {b}"),
    };
    let line = record.get("rule_line").and_then(Value::as_u64).unwrap_or(0);
    let n = record.get("n").and_then(Value::as_u64).unwrap_or(0);
    let key_hash = match s(record, "key") {
        "" => record.get("target").map_or("", |t| s(t, "sha256_prefix")),
        key => key,
    };
    let mut pairs: Vec<(&str, String)> = vec![
        ("Record", n.to_string()),
        ("Decision", id.to_string()),
        ("Time", time_full(s(record, "time"))),
        ("Person", both(s(record, "person"), s(record, "team"))),
        ("Client", s(record, "client").to_string()),
        ("Key hash", key_hash.to_string()),
        (
            "Request",
            both(s(record, "method"), s(record, "path")).replace(", ", " "),
        ),
        (
            "Model",
            match s(record, "provider") {
                "" => s(record, "model").to_string(),
                provider => format!("{} via {provider}", s(record, "model")),
            },
        ),
        (
            "Verdict",
            // The words the list's tag uses, not the record's own codes.
            match (s(record, "verdict"), answer_verdict(record)) {
                (_, "block") => "Allowed, answer withheld".to_string(),
                (_, "mask") => "Allowed, answer masked".to_string(),
                ("allow", _) => "Allowed".to_string(),
                ("refused", _) => format!("Refused: {}", code_words(s(record, "code"))),
                (verdict, _) => both(verdict, s(record, "code")),
            },
        ),
        (
            "Rule",
            if line > 0 {
                format!("{}, line {line}", s(record, "rule"))
            } else {
                s(record, "rule").to_string()
            },
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k, esc(&v)))
    .collect();
    match record.get("guardrails").and_then(Value::as_array) {
        None => {}
        Some(list) if list.is_empty() => pairs.push(("Guardrails", "Nothing found".into())),
        // One row per finding, its badge and then which guardrail and how many.
        Some(list) => pairs.extend(list.iter().map(|f| {
            (
                "Finding",
                // The guardrail name and its count stay on one line: "mask-pii, 1" never breaks at its dash.
                // Badge above, guardrail and count below, on every row: rows of different lengths read alike.
                format!(
                    r#"<span class="g-stack" style="gap: var(--space-1); justify-items: start">{}<span style="white-space: nowrap">{}, {}</span></span>"#,
                    badge(s(f, "action"), s(f, "kind")),
                    esc(s(f, "guardrail")),
                    f.get("count").and_then(Value::as_u64).unwrap_or(0)
                ),
            )
        })),
    }
    // The answer's own findings, each marked as found on the answer, not on the request.
    pairs.extend(answer_findings(record).iter().map(|f| {
        (
            "Finding",
            format!(
                r#"<span class="g-stack" style="gap: var(--space-1); justify-items: start">{}<span style="white-space: nowrap">{}, {}</span><span>on the answer</span></span>"#,
                badge(s(f, "action"), s(f, "kind")),
                esc(s(f, "guardrail")),
                f.get("count").and_then(Value::as_u64).unwrap_or(0)
            ),
        )
    }));
    match answer_verdict(record) {
        "pass" => pairs.push(("Answer", "Checked, nothing found".into())),
        "not_run" => pairs.push(("Answer", "Not checked: streamed".into())),
        _ => {}
    }
    if let Some(answer) = record.get("answer") {
        let n = answer.get("n").and_then(Value::as_u64).unwrap_or(0);
        pairs.push(("Answer record", n.to_string()));
    }
    let priced = ctx
        .usage
        .iter()
        .find(|u| !id.is_empty() && s(u, "id") == id)
        .map(|u| s(u, "price_source"));
    if let Some(source) = priced {
        pairs.push(("Price", esc(&price_word(source))));
    }
    pairs.extend(extra);
    for (label, key) in [
        ("Policy file", "policy_sha256"),
        ("Keys file", "keys_sha256"),
        ("Record hash", "hash"),
        ("Previous", "prev"),
    ] {
        pairs.push((label, esc(s(record, key))));
    }
    pairs.retain(|(_, v)| !v.is_empty() && v != "0");
    let same_policy = ctx
        .policy
        .filter(|text| sha256_hex(text.as_bytes()) == s(record, "policy_sha256"));
    let snippet = match (same_policy, line) {
        _ if s(record, "event") == "config_loaded" => change_snippet(record, ctx),
        (_, 0) => String::new(),
        (Some(text), line) => {
            let line = usize::try_from(line).unwrap_or(0);
            let lines: Vec<(usize, String, &str)> = text
                .lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l))
                .filter(|(n, _)| n + 1 >= line && *n <= line + 1)
                .map(|(n, l)| (n, yaml_line(l), if n == line { "hit" } else { "" }))
                .collect();
            code(&lines)
        }
        (None, _) => r#"<p class="t-small g-muted" style="margin: 0">The policy file has changed since this decision, so the lines that decided it are not shown. The hash above names the version that did.</p>"#.into(),
    };
    let mut actions = String::new();
    if line > 0 && same_policy.is_some() {
        actions += &link(
            &format!("Open policy at line {line}"),
            "",
            &format!("/console/policy?line={line}#line-{line}"),
            false,
        );
    }
    let person = s(record, "person");
    if s(record, "code") == "key_expired" && !ctx.read_only {
        actions += &link(
            "Issue a new key on People",
            "quiet",
            &format!(
                "/console/people?issue=1&amp;name={}&amp;team={}",
                enc(person),
                enc(s(record, "team"))
            ),
            false,
        );
    }
    if !person.is_empty() && person != "unknown" {
        let mine = Filter {
            show: "",
            q: person,
            model: "",
        };
        actions += &link(
            &format!("See {}'s other decisions", esc(person)),
            "quiet",
            &mine.href(0, ""),
            false,
        );
    }
    let kind = s(record, "verdict");
    let said = format!(
        r#"<div class="g-terminal t-mono" aria-label="The request"><span>{} {}</span><span class="g-terminal__out">Decision {}</span></div>"#,
        esc(s(record, "method")),
        esc(s(record, "path")),
        esc(id)
    );
    let broken = if ctx.broken == Some(n) && n > 0 {
        alert(
            "This record does not match its hash: it, or the record before it, was changed after it was written. What it says cannot be trusted until that is explained.",
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="g-scrim g-scrim--sheet">
<aside class="g-sheet" role="dialog" aria-modal="true" aria-labelledby="record-title">
<div class="g-pager"><span>{}</span><a class="g-btn g-btn--quiet g-btn--icon" href="{}" aria-label="Close this record" data-close>{}</a></div>
{broken}<div class="g-stack">
<h2 class="t-md" id="record-title" style="margin: 0">{title}</h2>
<p class="t-body g-muted" style="margin: 0">{lead}</p>
</div>
{}
{}
{snippet}
<div class="g-head__actions">{actions}</div>
</aside>
</div>"#,
        verdict(record),
        close,
        icon("close"),
        if kind.is_empty() || s(record, "method").is_empty() {
            String::new()
        } else {
            said
        },
        facts(&pairs),
    )
}

/// The record number a failed verification names: "record 40 ...".
fn broken_at(err: &str) -> Option<u64> {
    err.strip_prefix("record ")
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
}

pub fn audit(view: &AuditView<'_>) -> String {
    let query = view.query;
    let filter = Filter {
        show: query.get("verdict"),
        q: query.get("q").trim(),
        model: query.get("model"),
    };
    let today = today();
    let switch: String = view
        .chains
        .iter()
        .map(|(label, href, shown)| {
            link(&esc(label), if *shown { "" } else { "quiet" }, href, true)
        })
        .collect();
    // Verify sits with the chain's line under the records: it checks the data, it is not the page's main action.
    let verify = format!(
        r#"<form method="post" action="/console/audit/verify{}">{}</form>"#,
        if view.chain.is_empty() {
            String::new()
        } else {
            format!("?chain={}", esc(view.chain))
        },
        button("Verify chain now", "quiet", "submit", "")
    );
    let lead = if view.chain.is_empty() {
        "Every decision and admin change, in one chain.".to_string()
    } else {
        format!(
            "Every decision and change of organization {}, newest first, from its own chain.",
            esc(view.chain)
        )
    };
    let lead = lead.as_str();
    let (records, usage): (Vec<Value>, Vec<Value>) = match view.log {
        Ok(Some(text)) => text
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            // An attempts record repeats its decision's ID with the providers tried: it belongs to that decision.
            .filter(|r| s(r, "event") != "attempts")
            // Usage records are shown on the Spend page; the list is of decisions and changes.
            .partition(|r| s(r, "event") != "usage"),
        Ok(None) => (Vec::new(), Vec::new()),
        Err(err) => {
            let failed = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The audit log did not load",
                &format!(
                    "{} Requests are refused while Enterplace cannot write it: Enterplace does not forward what it cannot record.",
                    esc(err)
                ),
                &link("Try again", "", "/console/audit", false),
            );
            let main = format!("{}\n{failed}", head("Audit log", lead, ""));
            return tool_page("Audit log", view.admin, "/console/audit", query, &main, "");
        }
    };
    let records = fold_answers(records);
    if records.is_empty() {
        let none = crate::empty_page("Audit log", &crate::base(), true);
        let main = format!("{}\n{none}", head("Audit log", lead, &verify));
        return tool_page("Audit log", view.admin, "/console/audit", query, &main, "");
    }

    // Just after Verify chain now, keyboard focus goes to its result, so it is read out instead of the page top.
    let focus = match &view.verified {
        Some((at, _)) if at.elapsed().as_secs() < 10 => r#" tabindex="-1" data-focus"#,
        _ => "",
    };
    // The chain line, or the banner of a broken chain.
    let (banner, chain, broken) = match &view.verified {
        None => (
            String::new(),
            format!(
                r#"<span class="t-small g-muted">The chain has not been verified since Enterplace started. Verify chain now walks all {} records, as <span class="t-mono">enterplace audit verify</span> does.</span>"#,
                // Every record in the chain, usage ones too, as the CLI counts them.
                thousands(records.len() + usage.len())
            ),
            None,
        ),
        Some((at, Ok((0, _)))) => (
            String::new(),
            format!(
                r#"<span class="g-live t-small"{focus}>Chain verified {}: no records yet.</span>"#,
                ago(*at)
            ),
            None,
        ),
        Some((at, Ok((n, last)))) => (
            String::new(),
            // The whole hash: --expect-last needs all 64 characters, and a short one reads as records removed.
            format!(
                r#"<div class="g-stack" style="gap: var(--space-2)"{focus}><span class="g-live t-small">Chain verified {}: unbroken from record 1 to record {}. Its last hash:</span>
<span class="g-command g-command--value"><span class="g-command__text t-mono-sm" id="last-hash">{}</span><button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="last-hash">{}Copy</button></span>
<span class="t-small g-muted">Keep it somewhere Enterplace's host cannot write. Later, <span class="t-mono">enterplace audit verify --expect-last</span> with it proves no record up to it was changed or removed.</span></div>"#,
                ago(*at),
                thousands(usize::try_from(*n).unwrap_or(0)),
                esc(last),
                icon("copy")
            ),
            None,
        ),
        Some((at, Err(err))) => {
            let n = broken_at(err);
            let open = n
                .and_then(|n| {
                    records
                        .iter()
                        .find(|r| r.get("n").and_then(Value::as_u64) == Some(n))
                })
                .map(|r| {
                    link(
                        &format!(
                            "Open record {}",
                            thousands(n.map_or(0, |n| usize::try_from(n).unwrap_or(0)))
                        ),
                        "",
                        &filter.href(0, &rid(r)),
                        false,
                    )
                })
                .unwrap_or_default();
            (
                format!(
                    r#"<div class="g-banner" role="alert" style="border-color: var(--flame)"{focus}>
<span class="t-body">The chain is broken: {}</span>
<span class="g-head__actions">{open}</span>
</div>
"#,
                    esc(err)
                ),
                format!(
                    r#"<span class="t-small g-muted">Last verification {}: {}</span>"#,
                    ago(*at),
                    match n {
                        Some(n) if n > 1 =>
                            format!("records 1 to {} hold, then record {} does not.", n - 1, n),
                        Some(_) => "record 1 does not hold.".to_string(),
                        None => "the log could not be walked.".to_string(),
                    }
                ),
                Some(n.unwrap_or(0)),
            )
        }
    };

    // Requests only: admin records carry a verdict too, and are not requests through the gateway.
    let request_today = |r: &&Value| s(r, "time").starts_with(&today) && r.get("event").is_none();
    let today_where = |keep: &dyn Fn(&Value) -> bool| {
        records
            .iter()
            .filter(|r| request_today(r) && keep(r))
            .count()
    };
    let checked_today = today_where(&|r| !s(r, "verdict").is_empty());
    let blocked_today = today_where(&|r| blocked(r));
    let refused_today =
        today_where(&|r| s(r, "verdict") == "refused" && s(r, "code") != "guardrail_blocked");
    let stats = format!(
        r#"<div class="g-panel g-stats"{}>
<div class="g-stat"><p class="g-stat__figure t-lg">{}</p><p class="g-stat__label t-small">requests checked today</p></div>
<div class="g-stat"><p class="g-stat__figure t-lg">{}</p><p class="g-stat__label t-small">refused today</p></div>
<div class="g-stat"><p class="g-stat__figure t-lg">{}</p><p class="g-stat__label t-small">blocked by a guardrail today</p></div>
</div>"#,
        if broken.is_some() {
            r#" style="display: none""#
        } else {
            ""
        },
        thousands(checked_today),
        thousands(refused_today),
        thousands(blocked_today)
    );

    let mut models: Vec<&str> = records
        .iter()
        .map(|r| s(r, "model"))
        .filter(|m| !m.is_empty())
        .collect();
    models.sort_unstable();
    models.dedup();
    let options: String = models
        .iter()
        .map(|m| {
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                esc(m),
                if *m == filter.model { " selected" } else { "" },
                esc(m)
            )
        })
        .collect();
    let shown_now = if SHOW.iter().any(|(v, _)| *v == filter.show) {
        filter.show
    } else {
        "all"
    };
    let tabs: String = SHOW
        .iter()
        .map(|(value, label)| {
            format!(
                r#"<button class="g-tab t-body" type="submit" name="verdict" value="{value}" aria-pressed="{}">{label}</button>"#,
                if *value == shown_now { "true" } else { "false" }
            )
        })
        .collect();
    let toolbar = format!(
        r#"<form class="g-toolbar" method="get" action="/console/audit">
<div class="g-search">{}<input class="g-input t-body" type="search" name="q" value="{}" aria-label="Search the audit log" placeholder="Person, team, ID or key hash"></div>
<div class="g-tabs" role="group" aria-label="Show">{tabs}</div>
<div class="g-select-wrap"><select class="g-input g-select t-body" name="model" aria-label="Model" data-submit><option value="">Every model</option>{options}</select>{}</div>
</form>"#,
        icon("search"),
        esc(filter.q),
        icon("down")
    );

    let ctx = Context {
        records: &records,
        usage: &usage,
        policy: view.policy,
        loaded: view.loaded,
        broken,
        read_only: view.read_only,
        kills: view.kills.as_ref().map_or(&[], Vec::as_slice),
    };
    let shown: Vec<&Value> = records.iter().rev().filter(|r| filter.keeps(r)).collect();
    let selected = query.get("record");
    let page = page_number(query).min(shown.len().div_ceil(PER_PAGE).max(1));
    let list = if shown.is_empty() {
        empty(
            &motif(&["", "", ""], &["empty"], (3, 1), false, true),
            "No decision matches",
            "No decision matches this person, team, ID, key hash or model in the audit log.",
            &link("Show every decision", "quiet", "/console/audit", false),
        )
    } else {
        let rows = &shown[(page - 1) * PER_PAGE..(page * PER_PAGE).min(shown.len())];
        let caution = if broken.is_some() {
            r#"<p class="t-small g-muted" style="margin: 0">Records from the one named above onwards cannot be trusted until it is explained.</p>"#
        } else {
            ""
        };
        let (table, noun) = if shown_now == "changes" {
            (
                changes_table(rows, selected, &filter, page, &ctx),
                "changes",
            )
        } else {
            (audit_table(rows, selected, &filter, page), "decisions")
        };
        format!(
            "<div class=\"g-panel g-stack\">\n{caution}\n{table}\n{}\n</div>",
            pages_of(shown.len(), page, noun, |p| filter.href(p, ""))
        )
    };
    let close = filter.href(page, "");
    let sheet = if selected.is_empty() {
        String::new()
    } else {
        let number = |r: &Value| r.get("n").and_then(Value::as_u64).map(|n| n.to_string());
        records
            .iter()
            .find(|r| {
                rid(r) == selected
                    || number(r).as_deref() == Some(selected)
                    || r.get("answer").and_then(number).as_deref() == Some(selected)
            })
            .map_or_else(
                || missing_sheet(selected, &close),
                |r| record_sheet(r, &ctx, &close),
            )
    };
    let banner = kills_banner(view.kills, view.may_restore) + &banner;
    let main = format!(
        "{banner}{}\n{}\n\n{stats}\n\n{toolbar}\n\n{list}\n<div class=\"g-stack\" style=\"gap: var(--space-2)\">{chain}{verify}</div>",
        head("Audit log", lead, &switch),
        // Sign-ins and setup only, no request yet: the page says what fills it above those records.
        if records.iter().all(|r| r.get("event").is_some()) {
            crate::empty_page("Audit log", &crate::base(), true)
        } else {
            String::new()
        }
    );
    tool_page(
        "Audit log",
        view.admin,
        "/console/audit",
        query,
        &main,
        &sheet,
    )
}

// ---------------------------------------------------------------- people and workloads

/// How to point the OpenAI SDKs, Codex, Gemini CLI and Claude Code at the gateway at `base` with `key`, ready to paste.
pub(crate) fn tool_lines(base: &str, key: &str) -> Vec<String> {
    vec![
        "# OpenAI SDKs and OpenAI-compatible tools".into(),
        format!("export OPENAI_BASE_URL={base}/v1"),
        format!("export OPENAI_API_KEY={key}"),
        "# Codex: in ~/.codex/config.toml set model_provider = \"enterplace\" and".into(),
        format!(
            "#   [model_providers.enterplace] base_url = \"{base}/v1\", env_key = \"ENTERPLACE_KEY\", wire_api = \"responses\""
        ),
        format!("export ENTERPLACE_KEY={key}"),
        "# Gemini CLI".into(),
        format!("export GOOGLE_GEMINI_BASE_URL={base}"),
        format!("export GEMINI_API_KEY={key}"),
        "# Claude Code".into(),
        format!("export ANTHROPIC_BASE_URL={base}"),
        format!("export ANTHROPIC_API_KEY={key}"),
    ]
}

// ---------------------------------------------------------------- provider credentials

/// A dialog of the credentials page. Values typed are never sent back: a refused form comes back without them.
pub enum CredentialDialog {
    None,
    Add {
        name: String,
        provider: String,
        error: String,
    },
    Rotate {
        name: String,
        error: String,
    },
    Remove {
        name: String,
        error: String,
    },
}

impl CredentialDialog {
    pub fn from_query(query: &Form) -> Self {
        let error = String::new();
        if query.get("add") == "1" {
            Self::Add {
                name: String::new(),
                provider: String::new(),
                error,
            }
        } else if !query.get("rotate").is_empty() {
            Self::Rotate {
                name: query.get("rotate").to_string(),
                error,
            }
        } else if !query.get("remove").is_empty() {
            Self::Remove {
                name: query.get("remove").to_string(),
                error,
            }
        } else {
            Self::None
        }
    }
}

pub struct CredentialsView<'a> {
    pub admin: &'a str,
    pub query: &'a Form,
    /// `None` without a store. `Err` with the store and no master key: why the feature is off.
    pub credentials: Option<Result<Vec<enterplace_core::store::Credential>, String>>,
    /// The providers of the policy that name a credential, as (provider, credential).
    pub named: Vec<(String, String)>,
    pub dialog: CredentialDialog,
    pub read_only: bool,
}

fn secret_field(id: &str, error: &str) -> String {
    field(&Field {
        id,
        name: "value",
        label: "Provider key",
        value: "",
        mono: true,
        extra: r#" type="password" required aria-required="true" autocomplete="off" spellcheck="false""#,
        hint: "Sealed in the store with the master key. It is never shown again, here or anywhere.",
        error,
    })
}

fn credential_dialog(view: &CredentialsView<'_>) -> String {
    let cancel = close_link("Cancel", "quiet", "/console/credentials");
    let problem = |error: &str| {
        if error.is_empty() {
            String::new()
        } else {
            format!(
                r#"<p class="g-field__error t-small" role="alert" style="margin: 0">{}</p>"#,
                esc(error)
            )
        }
    };
    match &view.dialog {
        CredentialDialog::None => String::new(),
        CredentialDialog::Add {
            name,
            provider,
            error,
        } => {
            let fields = field(&Field {
                id: "credential-name",
                name: "name",
                label: "Name",
                value: name,
                mono: true,
                extra: r#" required aria-required="true" autocomplete="off" autofocus placeholder="openai-prod""#,
                hint: "A provider in the policy names it with credential: and this name.",
                error: "",
            }) + &field(&Field {
                id: "credential-provider",
                name: "provider",
                label: "Provider",
                value: provider,
                mono: true,
                extra: r#" required aria-required="true" autocomplete="off" placeholder="openai""#,
                hint: "The vendor the key is for, so the list says which is which.",
                error: "",
            }) + &secret_field("credential-value", "");
            dialog(
                "add-title",
                "Add a provider credential",
                "The key Enterplace sends to a provider, kept in the store sealed with AES-256-GCM under the master key. After it is saved only its name and last 4 characters are shown.",
                &format!(
                    r#"<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/credentials/add">{fields}{}<div class="g-dialog__actions">{cancel}{}</div></form>"#,
                    problem(error),
                    button("Add credential", "", "submit", "")
                ),
            )
        }
        CredentialDialog::Rotate { name, error } => dialog(
            "rotate-title",
            "Rotate this credential?",
            &format!(
                "Every gateway on this store sends the new value of <span class=\"t-mono\">{}</span> within 2 seconds, with no restart. Requests already sent finish with the old one.",
                esc(name)
            ),
            &format!(
                r#"<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/credentials/rotate"><input type="hidden" name="name" value="{}">{}{}<div class="g-dialog__actions">{cancel}{}</div></form>"#,
                esc(name),
                secret_field("rotate-value", ""),
                problem(error),
                button("Rotate", "", "submit", "")
            ),
        ),
        CredentialDialog::Remove { name, error } => {
            let n = esc(name);
            let confirm = field(&Field {
                id: "remove-type",
                name: "confirm",
                label: "Name, to confirm",
                value: "",
                mono: true,
                extra: &format!(
                    r#" required aria-required="true" autocomplete="off" autofocus data-confirm="{n}" data-button="remove-button""#
                ),
                hint: "",
                error: &esc(error),
            });
            dialog(
                "remove-title",
                "Remove this credential?",
                &format!(
                    "The sealed value of <span class=\"t-mono\">{n}</span> is deleted from the store. This cannot be undone. Type <span class=\"t-mono\">{n}</span> to confirm."
                ),
                &format!(
                    r#"<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/credentials/remove"><input type="hidden" name="name" value="{n}">{confirm}<div class="g-dialog__actions">{cancel}{}</div></form>"#,
                    button(
                        "Remove credential",
                        "flame",
                        "submit",
                        r#" id="remove-button""#
                    )
                ),
            )
        }
    }
}

pub fn credentials(view: &CredentialsView<'_>) -> String {
    let title = "Provider credentials";
    let here = "/console/credentials";
    let lead = "Provider keys, stored encrypted. Never shown after saving.";
    let picture = motif(&["", "flame"], &["empty"], (2, 1), true, true);
    let list = match &view.credentials {
        None => {
            let off = empty(
                &picture,
                "Credentials need the store",
                "Provider credentials are kept in Postgres, sealed with a master key, and this gateway's policy has no store: section. Keep each provider key in an environment variable with key_env (or a file with key_file), or add store: to the policy and set ENTERPLACE_MASTER_KEY.",
                "",
            );
            let main = format!("{}\n{off}", head(title, lead, ""));
            return tool_page(title, view.admin, here, view.query, &main, "");
        }
        Some(Err(off)) => {
            let off = empty(&picture, "Credentials are off", &esc(off), "");
            let main = format!("{}\n{off}", head(title, lead, ""));
            return tool_page(title, view.admin, here, view.query, &main, "");
        }
        Some(Ok(list)) => list,
    };
    let add = if view.read_only {
        String::new()
    } else {
        link("Add a credential", "", "/console/credentials?add=1", false)
    };
    let toast = match (view.query.get("done"), view.query.get("name")) {
        ("", _) | (_, "") => String::new(),
        (done, name) => {
            let what = match done {
                "added" => "is added. A provider can name it with credential: now.",
                "rotated" => "is rotated. Every gateway sends the new value within 2 seconds.",
                _ => "is removed.",
            };
            format!(
                r#"<div class="g-toasts"><div class="g-toast" role="status" tabindex="-1" data-focus><span class="g-toast__text t-body">Credential {} {what}</span></div></div>"#,
                esc(name)
            )
        }
    };
    let overlay = format!("{}{toast}", credential_dialog(view));
    let table = if list.is_empty() {
        empty(
            &motif(&["", "", "", ""], &["empty", "empty"], (2, 1), true, true),
            "No credentials yet",
            "Add a provider key here, then name it in the policy with credential: in place of key_env.",
            &add,
        )
    } else {
        let mut rows = String::new();
        for c in list {
            let used: Vec<&str> = view
                .named
                .iter()
                .filter(|(_, n)| *n == c.name)
                .map(|(p, _)| p.as_str())
                .collect();
            let used = if used.is_empty() {
                "not named".to_string()
            } else {
                used.join(", ")
            };
            let rotated = match (&c.rotated_at, &c.rotated_by) {
                (Some(at), Some(by)) => format!("{} by {}", time_full(at), esc(by)),
                _ => "never".to_string(),
            };
            let actions = if view.read_only {
                String::new()
            } else {
                link(
                    "Rotate",
                    "quiet",
                    &format!("{here}?rotate={}", enc(&c.name)),
                    true,
                ) + &link(
                    "Remove",
                    "quiet",
                    &format!("{here}?remove={}", enc(&c.name)),
                    true,
                )
            };
            let _ = write!(
                rows,
                r#"<tr><td>{}<span class="g-table__sub">{}</span></td><td>{}</td><td class="g-table__wide">{}</td><td class="g-table__wide">{} by {}</td><td class="g-table__wide">{rotated}</td><td><span class="g-head__actions">{actions}</span></td></tr>"#,
                esc(&c.name),
                esc(&c.provider),
                esc(&c.fingerprint),
                esc(&used),
                time_full(&c.created_at),
                esc(&c.created_by),
            );
        }
        format!(
            r#"<div class="g-panel g-stack">
<div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm">
<thead class="t-tag"><tr><th>Name</th><th>Key</th><th>Used by</th><th>Added</th><th>Rotated</th><th>Change</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>
</div>"#
        )
    };
    let main = format!("{}\n{table}", head(title, lead, &add));
    tool_page(title, view.admin, here, view.query, &main, &overlay)
}

// ---------------------------------------------------------------- policy

/// Where the policy page's policy comes from: the file, or a live version in the store.
pub struct PolicySource {
    /// The live version's number, when the policy is kept in the store.
    pub version: Option<i64>,
    /// Links in the page head: edit, versions, export.
    pub actions: String,
    /// A warning above the policy, as markup: the file differs from the live version.
    pub banner: String,
    /// The gateways on the store, as their heartbeats say. Empty without a store, or for a role that does not see
    /// records.
    pub replicas: Vec<enterplace_core::store::Replica>,
}

pub fn policy(
    admin: &str,
    query: &Form,
    path: &Path,
    text: &Result<Option<String>, String>,
    loaded: &Result<Loaded, Vec<String>>,
    source: &PolicySource,
) -> String {
    let title = "Policy";
    let file = esc(&path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    ));
    let text = match text {
        Ok(Some(text)) => text,
        Ok(None) | Err(_) => {
            let why = match text {
                Err(err) => esc(err),
                _ => format!("There is no file at {}.", esc(&path.display().to_string())),
            };
            let failed = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The policy file did not load",
                &why,
                &link("Try again", "", "/console/policy", false),
            );
            let main = format!(
                "{}\n{failed}",
                head(title, "One file decides every request.", "")
            );
            return tool_page(title, admin, "/console/policy", query, &main, "");
        }
    };
    // Problems on a line of the policy file go under that line, as the PolicyError screen shows. Others are listed above.
    let prefix = format!("{}:", path.display());
    let mut on_line: HashMap<usize, Vec<String>> = HashMap::new();
    let mut elsewhere = Vec::new();
    if let Err(problems) = loaded {
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
    let hit: usize = query.get("line").parse().unwrap_or(0);
    let mut lines = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let kind = if on_line.contains_key(&n) {
            "error"
        } else if n == hit {
            "hit"
        } else {
            ""
        };
        lines.push((n, yaml_line(line), kind));
        for msg in on_line.get(&n).into_iter().flatten() {
            lines.push((
                0,
                format!("Line {n}: {}", esc(msg).replace('\n', "<br>")),
                "note",
            ));
        }
    }
    let (lead, side) = match loaded {
        Ok(loaded) => {
            let providers: String = loaded
                .providers
                .iter()
                .map(|p| {
                    row(
                        &esc(&p.name),
                        &format!(
                            "{} at {}. Serves {}.",
                            p.kind.word(),
                            esc(&p.url),
                            esc(&p.models.join(", "))
                        ),
                        "",
                        true,
                    )
                })
                .collect();
            let rules: String = loaded
                .policy
                .rule_list()
                .iter()
                .map(|r| {
                    let who = match &r.who {
                        Who::Team(team) => format!("Team {}", esc(team)),
                        Who::Name(name) => esc(name),
                        Who::Tag(tag) => format!("Keys tagged {}", esc(tag)),
                        Who::Any => "Everyone else".into(),
                    };
                    let models = match &r.models {
                        Models::Any => "every model".to_string(),
                        Models::Only(m) if m.is_empty() => "no model".to_string(),
                        Models::Only(m) => esc(&m.join(", ")),
                    };
                    // What else the rule does: its guardrails, budget and rate limit, each in a sentence.
                    let mut meta = format!("{who} may use {models}.");
                    if !r.guardrails.is_empty() {
                        // A guardrail name is an identifier: it never breaks at its dash.
                        let names: Vec<String> = r
                            .guardrails
                            .iter()
                            .map(|g| {
                                format!(
                                    r#"<span class="t-mono" style="white-space: nowrap">{}</span>"#,
                                    esc(&g.name)
                                )
                            })
                            .collect();
                        let _ = write!(meta, " Guardrails: {}.", names.join(", "));
                    }
                    if let Some(b) = r.limits.budget() {
                        let _ = write!(meta, " Budget {} a {}.", money(b.usd), b.per.word());
                    }
                    if let Some(rpm) = r.limits.rpm {
                        let _ = write!(meta, " {rpm} requests a minute each.");
                    }
                    row(
                        &esc(&r.name),
                        &meta,
                        &link(
                            &format!("Line {}", r.line),
                            "quiet",
                            &format!("/console/policy?line={0}#line-{0}", r.line),
                            true,
                        ),
                        true,
                    )
                })
                .collect();
            (
                match source.version {
                    Some(v) => format!(
                        "Version {v} in the store decides every request: {} and {}, read in order, the first that names the caller decides. Edit it here: each save is a new version, checked as <span class=\"t-mono\">enterplace check</span> checks a file.",
                        enterplace_core::count(loaded.policy.rules(), "rule"),
                        enterplace_core::count(loaded.providers.len(), "provider")
                    ),
                    None => format!(
                        "One file decides every request: {} and {}, read in order, the first that names the caller decides. Read only here: change the file and run <span class=\"t-mono\">enterplace check</span>.",
                        enterplace_core::count(loaded.policy.rules(), "rule"),
                        enterplace_core::count(loaded.providers.len(), "provider")
                    ),
                },
                format!(
                    r#"<aside class="g-stack" aria-label="About this file">
<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">Rules</h2><div class="g-list">{rules}</div></div>
<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">Providers</h2><div class="g-list">{providers}</div><p class="t-small g-muted" style="margin: 0">A provider key stays in its environment variable and is never shown here.</p></div>
{}
</aside>"#,
                    gateways(&source.replicas)
                ),
            )
        }
        Err(problems) => (
            format!(
                "<span class=\"t-mono\">enterplace check</span> refuses this file: {}, each on its line below. A running gateway keeps the version it loaded.",
                enterplace_core::count(problems.len(), "problem")
            ),
            String::new(),
        ),
    };
    let banner = if elsewhere.is_empty() {
        source.banner.clone()
    } else {
        format!(
            r#"<div class="g-banner" role="alert" style="border-color: var(--flame)"><span class="t-body">{}</span></div>"#,
            elsewhere
                .iter()
                .map(|p| esc(p))
                .collect::<Vec<_>>()
                .join("<br>")
        )
    };
    let main = format!(
        r#"{}
{banner}
<div class="g-split">
<div class="g-panel g-stack g-split__wide">
<div class="g-pager"><span class="t-mono-lg">{file}</span>{}</div>
{}
<p class="t-small g-muted" style="margin: 0">{}</p>
</div>
{side}
</div>"#,
        head(title, &lead, &source.actions),
        match source.version {
            Some(v) => tag("allow", &format!("Version {v}, live"), ""),
            None => tag("", "Read only", ""),
        },
        code(&lines),
        match source.version {
            Some(v) => format!("Live version {v} in the store, when this page was opened."),
            None => format!(
                "Read from {} when this page was opened.",
                esc(&path.display().to_string())
            ),
        }
    );
    tool_page(title, admin, "/console/policy", query, &main, "")
}

/// The policy page's Gateways panel: every gateway on the store, so an admin sees which run and which went quiet.
fn gateways(replicas: &[enterplace_core::store::Replica]) -> String {
    if replicas.is_empty() {
        return String::new();
    }
    let rows: String = replicas
        .iter()
        .map(|r| {
            row(
                &esc(&r.host),
                &format!(
                    "Version {}, schema {}. Started {}, last heartbeat {}.",
                    esc(&r.version),
                    esc(&r.schema),
                    esc(&r.started),
                    esc(&r.seen)
                ),
                &if r.healthy {
                    tag("allow", "Healthy", "")
                } else {
                    tag("refused", "Silent", "")
                },
                true,
            )
        })
        .collect();
    format!(
        r#"<div class="g-panel g-stack"><h2 class="t-md" style="margin: 0">Gateways</h2><div class="g-list">{rows}</div><p class="t-small g-muted" style="margin: 0">A gateway is silent when it wrote no heartbeat to the store in 10 seconds.</p></div>"#
    )
}

// ---------------------------------------------------------------- spend

/// What the Spend page reads: the audit log and the policy as `enterplace check` reads it.
pub struct SpendView<'a> {
    pub admin: &'a str,
    pub query: &'a Form,
    pub log: &'a Result<Option<String>, String>,
    pub loaded: &'a Result<Loaded, Vec<String>>,
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// The smallest of 1, 2, 5 or 10 times a power of ten that is at least `x`: the top of a chart's scale.
fn nice_top(x: f64) -> f64 {
    if x <= 0.0 || !x.is_finite() {
        return 1.0;
    }
    let power = 10f64.powf(x.log10().floor());
    [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .map(|m| m * power)
        .find(|top| *top >= x * 0.999_999)
        .unwrap_or(10.0 * power)
}

/// Spent, requests and tokens of one model or person.
#[derive(Default)]
struct Tally {
    usd: f64,
    requests: usize,
    tokens: u64,
}

/// One budget of the policy, with what was spent against it in its current period.
struct Meter {
    label: String,
    rule_line: usize,
    usd: f64,
    per_day: bool,
    spent: f64,
    /// The time of the record that took spend to the budget, if one did.
    ran_out: Option<String>,
    /// The rule that sets it, or for a key's own budget the key's hash prefix.
    rule: String,
    key: Option<String>,
    /// Requests it refused in its current period.
    refused: usize,
}

fn days_in(year: u32, month: u32) -> usize {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The Spend screen, from the usage records of this month (UTC) and the budgets of the policy.
pub fn spend(view: &SpendView<'_>) -> String {
    let today = today();
    let part = |range: std::ops::Range<usize>| {
        today
            .get(range)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(1)
    };
    let (year, month, day_now) = (part(0..4), part(5..7).clamp(1, 12), part(8..10) as usize);
    let this_month = today.get(..7).unwrap_or("");
    let days = days_in(year, month);
    let name = MONTHS[month as usize - 1];
    let next = format!("1 {}", MONTHS[month as usize % 12]);
    let lead_none = "What each team spends, by model.";
    let text = match view.log {
        Ok(text) => text.as_deref().unwrap_or(""),
        Err(err) => {
            let failed = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The audit log did not load",
                &format!("{} Spend is read from it.", esc(err)),
                &link("Try again", "", "/console/spend", false),
            );
            let main = format!("{}\n{failed}", head("Spend", lead_none, ""));
            return tool_page("Spend", view.admin, "/console/spend", view.query, &main, "");
        }
    };
    let rules = view
        .loaded
        .as_ref()
        .map(|l| l.policy.rule_list())
        .unwrap_or_default();
    let mut meters: Vec<(Meter, Who)> = rules
        .iter()
        .filter_map(|rule| {
            let budget = rule.limits.budget()?;
            let label = match &rule.who {
                Who::Team(team) => team.clone(),
                Who::Name(name) => name.clone(),
                Who::Tag(tag) => format!("tag {tag}"),
                Who::Any => String::new(),
            };
            Some((
                Meter {
                    label,
                    rule_line: rule.line,
                    usd: budget.usd,
                    per_day: budget.per == enterplace_core::policy::Period::Day,
                    spent: 0.0,
                    ran_out: None,
                    rule: rule.name.clone(),
                    key: None,
                    refused: 0,
                },
                rule.who.clone(),
            ))
        })
        .collect();
    // A key's own budget, from the keys file, after the rules' budgets. `Who::Any` is a placeholder: a key meter
    // counts by its hash.
    let mut keyed: Vec<(Meter, Who)> = view
        .loaded
        .as_ref()
        .map(|l| {
            l.policy
                .entries()
                .filter_map(|(_, p)| {
                    let budget = p.budget?;
                    Some((
                        Meter {
                            label: format!("{}'s key", p.name),
                            rule_line: 0,
                            usd: budget.usd,
                            per_day: budget.per == enterplace_core::policy::Period::Day,
                            spent: 0.0,
                            ran_out: None,
                            rule: String::new(),
                            key: Some(p.key.clone()),
                            refused: 0,
                        },
                        Who::Any,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    keyed.sort_by(|a, b| a.0.label.cmp(&b.0.label));
    meters.extend(keyed);
    // A budget for everyone is per person: the meter follows whoever has spent most against it.
    let mut each: HashMap<(usize, String), f64> = HashMap::new();

    let (mut total, mut unknown, mut stopped) = (0.0, 0usize, 0usize);
    let mut daily = vec![0.0; days];
    let mut models: HashMap<String, (String, Tally)> = HashMap::new();
    let mut sources: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
    let mut people: HashMap<String, (Tally, HashMap<String, f64>)> = HashMap::new();
    for line in text.lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let time = s(&record, "time");
        if time.get(..7) != Some(this_month) {
            continue;
        }
        if s(&record, "event") != "usage" {
            stopped += usize::from(s(&record, "verdict") == "refused");
            let today_only = time.get(..10) == Some(today.as_str());
            for (meter, _) in &mut meters {
                let mine = match &meter.key {
                    Some(key) => {
                        s(&record, "code") == "key_budget_exceeded" && s(&record, "key") == key
                    }
                    None => {
                        s(&record, "code") == "budget_exceeded" && s(&record, "rule") == meter.rule
                    }
                };
                meter.refused += usize::from(mine && (today_only || !meter.per_day));
            }
            continue;
        }
        let usd = record["charged_usd"].as_f64().unwrap_or_default();
        let count = |key: &str| record[key].as_u64().unwrap_or_default();
        let tokens = count("input_tokens")
            + count("output_tokens")
            + count("cache_read_tokens")
            + count("cache_write_tokens");
        unknown += usize::from(record["cost_usd"].is_null());
        total += usd;
        let day: usize = time.get(8..10).and_then(|d| d.parse().ok()).unwrap_or(1);
        if let Some(slot) = daily.get_mut(day.saturating_sub(1)) {
            *slot += usd;
        }
        let (model, person, team) = (
            s(&record, "model"),
            s(&record, "person"),
            s(&record, "team"),
        );
        let entry = models
            .entry(model.to_string())
            .or_insert_with(|| (s(&record, "provider").to_string(), Tally::default()));
        entry.1.usd += usd;
        entry.1.requests += 1;
        entry.1.tokens += tokens;
        // Records written before price_source existed say nothing of it, and a null one had no price.
        let source = match (s(&record, "price_source"), record["cost_usd"].is_null()) {
            ("", true) => "none",
            (source, _) => source,
        };
        if !source.is_empty() {
            sources
                .entry(model.to_string())
                .or_default()
                .insert(source.to_string());
        }
        let who = people.entry(person.to_string()).or_default();
        who.0.usd += usd;
        who.0.requests += 1;
        *who.1.entry(model.to_string()).or_default() += usd;
        let today_only = time.get(..10) == Some(today.as_str());
        for (i, (meter, rule_who)) in meters.iter_mut().enumerate() {
            if meter.per_day && !today_only {
                continue;
            }
            let spent = match (&meter.key, rule_who) {
                (Some(key), _) if s(&record, "key") == key => {
                    meter.spent += usd;
                    meter.spent
                }
                (Some(_), _) => continue,
                (None, rule_who) => match rule_who {
                    Who::Team(t) if t == team => {
                        meter.spent += usd;
                        meter.spent
                    }
                    Who::Name(n) if n == person => {
                        meter.spent += usd;
                        meter.spent
                    }
                    Who::Any => {
                        let spent = each.entry((i, person.to_string())).or_default();
                        *spent += usd;
                        if *spent > meter.spent || meter.label.is_empty() {
                            meter.spent = *spent;
                            meter.label = person.to_string();
                        }
                        *spent
                    }
                    _ => continue,
                },
            };
            if spent >= meter.usd && meter.ran_out.is_none() {
                meter.ran_out = Some(time.to_string());
            }
        }
    }

    if total == 0.0 && meters.is_empty() && view.loaded.is_ok() {
        // Requests that cost nothing (the demo model) would draw an empty chart and rank people at $0: one line says it.
        let none = if people.is_empty() && stopped == 0 {
            crate::empty_page("Spend", &crate::base(), true)
        } else {
            empty(
                &motif(&["", "", ""], &["empty", "empty"], (3, 1), false, true),
                "No spend yet",
                if models.is_empty() {
                    "No request reached a provider yet."
                } else if models
                    .keys()
                    .all(|m| m == enterplace_core::usage::DEMO_MODEL)
                {
                    "Demo requests are free."
                } else {
                    "No request so far had a price."
                },
                &link(
                    "Add a budget",
                    "",
                    "/console/start?track=limit#step-5",
                    false,
                ),
            )
        };
        let main = format!("{}\n{none}", head("Spend", lead_none, ""));
        return tool_page("Spend", view.admin, "/console/spend", view.query, &main, "");
    }

    let at = |time: &str| {
        let day: usize = time.get(8..10).and_then(|d| d.parse().ok()).unwrap_or(1);
        (day, time.get(11..16).unwrap_or("").to_string())
    };
    // The lead: the month's total, who ran out, and who is on pace to.
    let mut lead = format!("{} spent in {name} so far.", money(total));
    let mut on_pace = Vec::new();
    for (meter, who) in &meters {
        if meter.label.is_empty() {
            continue;
        }
        // A sentence does not start with a lower-case identifier: a team is named as one.
        let whose = if matches!(who, Who::Team(_)) {
            format!("Team {}", esc(&meter.label))
        } else {
            esc(&meter.label)
        };
        match &meter.ran_out {
            Some(time) => {
                let (day, _) = at(time);
                let until = if meter.per_day {
                    "tomorrow".to_string()
                } else {
                    next.clone()
                };
                let _ = write!(
                    lead,
                    " {whose} spent its {} on {day} {name} and is refused until {until}.",
                    money(meter.usd)
                );
            }
            None if !meter.per_day
                && meter.spent > 0.0
                && meter.usd / (meter.spent / day_now as f64) < days as f64 =>
            {
                on_pace.push(whose);
            }
            None => {}
        }
    }
    match on_pace.as_slice() {
        [] => {}
        [one] => {
            let _ = write!(lead, " {one} is on pace to run out before the month ends.");
        }
        [rest @ .., last] => {
            // Only the first name starts the sentence.
            let later = |w: &String| w.replacen("Team ", "team ", 1);
            let middle: Vec<String> = rest.iter().skip(1).map(later).collect();
            let first = rest.first().cloned().unwrap_or_default();
            let head = [first]
                .into_iter()
                .chain(middle)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                lead,
                " {head} and {} are on pace to run out before the month ends.",
                later(last)
            );
        }
    }
    let first_out = meters
        .iter()
        .filter_map(|(m, _)| m.ran_out.as_ref().map(|t| (t.clone(), m)))
        .filter(|(_, m)| !m.per_day && m.key.is_none())
        .min_by(|a, b| a.0.cmp(&b.0));
    let action = match &first_out {
        Some((_, meter)) => link(
            &format!("Edit the {} budget in the policy", esc(&meter.label)),
            "",
            &format!("/console/policy?line={}", meter.rule_line),
            false,
        ),
        None if meters.is_empty() => String::new(),
        None => link(
            "Edit the budgets in the policy",
            "",
            "/console/policy",
            false,
        ),
    };

    // The chart: one bar per day of the month, the pace that keeps every monthly budget inside its limit, and the
    // day the first budget ran out.
    let pace = meters
        .iter()
        .filter(|(m, who)| !m.per_day && !matches!(who, Who::Any) && m.key.is_none())
        .map(|(m, _)| m.usd)
        .sum::<f64>()
        / days as f64;
    let highest = daily.iter().copied().fold(0.0, f64::max);
    let top = nice_top(highest.max(pace));
    let mark = first_out.as_ref().map(|(time, _)| at(time).0);
    let mut bars = String::new();
    for (i, value) in daily.iter().enumerate() {
        if i < day_now {
            let _ = write!(
                bars,
                r#"<div class="g-bar" style="--g-bar-value: {:.1}%" title="{} {name}: {}"></div>"#,
                value / top * 100.0,
                i + 1,
                money(*value)
            );
        } else {
            bars.push_str(r#"<div class="g-bar g-bar--empty"></div>"#);
        }
    }
    let shown = [1, 5, 10, 15, 20, 25, days];
    let day_marks: String = (1..=days)
        .map(|day| {
            if Some(day) == mark {
                format!(r#"<span class="g-chart__mark">{day}</span>"#)
            } else if shown.contains(&day) {
                format!("<span>{day}</span>")
            } else {
                "<span></span>".to_string()
            }
        })
        .collect();
    let peak = daily
        .iter()
        .enumerate()
        .take(day_now)
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map_or(1, |(i, _)| i + 1);
    let later = if day_now < days {
        format!(" {} to {days} {name} have not happened yet.", day_now + 1)
    } else {
        String::new()
    };
    let label = format!(
        "Spend per day in {name}. The highest day is {peak} {name} at {}.{later}",
        money(daily.get(peak - 1).copied().unwrap_or_default())
    );
    let pace_line = if pace > 0.0 {
        format!(
            r#"<span class="g-chart__pace" style="--g-at: {:.1}%"></span>"#,
            pace / top * 100.0
        )
    } else {
        String::new()
    };
    let chart = format!(
        r#"<div class="g-chart" role="img" aria-label="{label}"><div class="g-chart__scale t-mono-sm"><span>{}</span><span>{}</span><span>{}</span></div><div class="g-chart__plot"><span class="g-chart__grid" style="--g-at: 50%"></span><span class="g-chart__grid" style="--g-at: 100%"></span>{pace_line}{bars}</div><div class="g-chart__days t-mono-sm">{day_marks}</div></div>"#,
        money(top),
        money(top / 2.0),
        money(0.0)
    );
    let mut caption = if pace > 0.0 {
        let above = daily.iter().take(day_now).filter(|v| **v > pace).count();
        format!(
            "The dashed line is {} a day, the pace that keeps every monthly budget inside its limit. {} of the {} days so far {} above it.",
            money(pace),
            above,
            day_now,
            if above == 1 { "is" } else { "are" }
        )
    } else {
        format!("Each bar is one day of {name}, UTC.")
    };
    if let Some((time, meter)) = &first_out {
        let _ = write!(
            caption,
            " The mark on {} {name} is when {} ran out.",
            at(time).0,
            esc(&meter.label)
        );
    }

    // Who spent most, each with a way to their requests.
    let mut ranked: Vec<_> = people.iter().collect();
    // By spend, then by requests: until something is spent, the busiest come first.
    ranked.sort_by(|a, b| {
        b.1.0
            .usd
            .total_cmp(&a.1.0.usd)
            .then(b.1.0.requests.cmp(&a.1.0.requests))
            .then(a.0.cmp(b.0))
    });
    let top_people: String = ranked
        .iter()
        .take(3)
        .map(|(person, (tally, by_model))| {
            let mostly = by_model
                .iter()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .map_or("", |(m, _)| m.as_str());
            row(
                &esc(person),
                &format!(
                    r#"Sent {} {}, {}, most of it on <span class="t-mono" style="white-space: nowrap">{}</span>."#,
                    thousands(tally.requests),
                    if tally.requests == 1 {
                        "request"
                    } else {
                        "requests"
                    },
                    money(tally.usd),
                    esc(mostly)
                ),
                &link(
                    "See these requests",
                    "quiet",
                    &format!("/console/audit?q={}", enc(person)),
                    true,
                ),
                true,
            )
        })
        .collect();
    let spenders = if top_people.is_empty() {
        format!(
            r#"<p class="t-small g-muted" style="margin: 0">Nobody has spent anything in {name} yet.</p>"#
        )
    } else {
        format!(r#"<div class="g-list">{top_people}</div>"#)
    };

    let budgets = if let Err(problems) = view.loaded {
        empty(
            &motif(&["", "flame"], &["empty"], (2, 1), true, true),
            "The policy file has problems",
            &format!(
                "{} in the policy file, so its budgets cannot be shown here. Enterplace keeps using the version it has.",
                enterplace_core::count(problems.len(), "problem")
            ),
            &link("Open the policy", "", "/console/policy", false),
        )
    } else if meters.is_empty() {
        empty(
            &motif(&["", "", ""], &["empty", "empty"], (3, 1), false, true),
            "No budgets yet",
            &format!(
                "Spend is being recorded: {} in {name} so far. Nothing stops it, because the policy sets no budget for any team.",
                money(total)
            ),
            &link("Add a budget to the policy", "", "/console/policy", false),
        )
    } else {
        let mut out = String::new();
        for (meter, who) in &meters {
            let pct = if meter.usd > 0.0 {
                (meter.spent / meter.usd * 100.0).round().min(100.0) as u32
            } else {
                0
            };
            let resets = if meter.per_day {
                "Resets at midnight UTC".to_string()
            } else {
                format!("Resets {next}")
            };
            let (note, state) = match &meter.ran_out {
                Some(time) => {
                    let (day, clock) = at(time);
                    let until = if meter.per_day {
                        "midnight UTC".to_string()
                    } else {
                        format!("it resets on {next}")
                    };
                    (
                        format!("Spent on {day} {name} at {clock}. Refused until {until}."),
                        r#" data-state="over""#,
                    )
                }
                None if meter.per_day => (format!("{resets}."), ""),
                None if meter.spent > 0.0 => {
                    let runs_out = (meter.usd / (meter.spent / day_now as f64)) as usize + 1;
                    if runs_out <= days {
                        (
                            format!("At this rate it runs out around {runs_out} {name}. {resets}."),
                            "",
                        )
                    } else {
                        (format!("At this rate it lasts the month. {resets}."), "")
                    }
                }
                None => (format!("Nothing spent yet. {resets}."), ""),
            };
            // A budget that refused a request is spent, even when held reservations, not charges, filled it.
            let state = if meter.refused > 0 {
                r#" data-state="over""#
            } else {
                state
            };
            let note = match (&meter.key, who) {
                (Some(_), _) => format!("The key's own budget, from the keys file. {note}"),
                (None, Who::Any) => {
                    format!("A budget for each person; the meter shows who has spent most. {note}")
                }
                _ => note,
            };
            // What the budget stopped, under its meter: the refusals are the reason to look.
            let note = match meter.refused {
                0 => note,
                n => format!(
                    "{note} Refused {} {}.",
                    enterplace_core::count(n, "request"),
                    if meter.per_day { "today" } else { "this month" }
                ),
            };
            let label = if meter.label.is_empty() {
                "each person"
            } else {
                meter.label.as_str()
            };
            let per = if meter.per_day { " today" } else { "" };
            let _ = write!(
                out,
                r#"<div class="g-meter"{state} style="--g-meter-value: {pct}%"><div class="g-meter__row"><span class="t-mono-lg">{}</span><span class="t-mono-sm">{} of {}{per}</span></div><div class="g-meter__track" role="meter" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100" aria-label="{} budget used"><div class="g-meter__fill"></div></div><span class="t-small g-muted">{note}</span></div>"#,
                esc(label),
                money(meter.spent),
                money(meter.usd),
                esc(label)
            );
        }
        out
    };

    let mut by_model: Vec<(&String, &(String, Tally))> = models.iter().collect();
    by_model.sort_by(|a, b| b.1.1.usd.total_cmp(&a.1.1.usd).then(a.0.cmp(b.0)));
    let model_rows: String = by_model
        .iter()
        .map(|(model, (provider, t))| {
            let priced: Vec<String> = sources
                .get(*model)
                .into_iter()
                .flatten()
                .map(|source| match source.as_str() {
                    "none" => "no price, cost unknown".to_string(),
                    source => format!("priced {}", price_word(source)),
                })
                .collect();
            format!(
                r#"<tr><td>{}</td><td class="g-table__num">{}</td><td class="g-table__wide">{}<span class="g-table__sub">{}</span></td><td class="g-table__num g-table__wide">{}</td><td class="g-table__num g-table__wide">{}</td></tr>"#,
                esc(model),
                money(t.usd),
                esc(provider),
                esc(&priced.join("; ")),
                thousands(t.requests),
                thousands(usize::try_from(t.tokens).unwrap_or(usize::MAX))
            )
        })
        .collect();
    // Only the sources this month's answers were priced from, in the order a price is looked up.
    let used: std::collections::BTreeSet<&str> =
        sources.values().flatten().map(String::as_str).collect();
    let named: Vec<&str> = [
        ("policy", "the prices section of the policy file"),
        (
            "builtin",
            "Enterplace's own table, checked against each provider's price list on 13 November 2026",
        ),
        (
            "litellm",
            "the LiteLLM table (MIT price map, pinned in this build)",
        ),
    ]
    .into_iter()
    .filter(|(key, _)| used.contains(key))
    .map(|(_, words)| words)
    .collect();
    let mut note = match named.as_slice() {
        [] => {
            "Prices: the policy file's prices, then Enterplace's own table, then the LiteLLM table."
                .to_string()
        }
        [one] => format!("Prices this month came from {one}."),
        many => format!(
            "Prices this month came from {} and {}.",
            many[..many.len() - 1].join(", "),
            many[many.len() - 1]
        ),
    };
    if unknown > 0 {
        let _ = write!(
            note,
            " {} reported no usage or had no price: each counts as what it reserved against a budget, or nothing without one.",
            if unknown == 1 {
                "1 answer".to_string()
            } else {
                format!("{} answers", thousands(unknown))
            }
        );
    }

    let main = format!(
        r#"{}

<div class="g-panel g-stack">
<h2 class="t-md" style="margin: 0">Spend per day, USD</h2>
{chart}
<p class="t-small g-muted" style="margin: 0">{caption}</p>
</div>

<div class="g-split">
<div class="g-panel g-stack">
<h2 class="t-md" style="margin: 0">Who spent most in {name}</h2>
{spenders}
</div>

<div class="g-panel g-stack">
<h2 class="t-md" style="margin: 0">Budgets</h2>
{budgets}
</div>
</div>

<div class="g-panel g-stack">
<h2 class="t-md" style="margin: 0">Spend by model</h2>
<div class="g-table-wrap"><table class="g-table g-table--stack t-mono-sm">
<thead class="t-tag"><tr><th>Model</th><th class="g-table__num">USD</th><th>Provider</th><th class="g-table__num">Requests</th><th class="g-table__num">Tokens</th></tr></thead>
<tbody>
{model_rows}
<tr><td>Stopped before sending</td><td class="g-table__num">0.00</td><td class="g-table__wide"></td><td class="g-table__num g-table__wide">{}</td><td class="g-table__num g-table__wide">0</td></tr>
</tbody>
</table></div>
<p class="t-small g-muted" style="margin: 0">{note}</p>
</div>"#,
        head("Spend", &lead, &action),
        thousands(stopped)
    );
    tool_page("Spend", view.admin, "/console/spend", view.query, &main, "")
}

/// Where a usage record's price came from, from its `price_source`.
fn price_word(source: &str) -> String {
    match source {
        "policy" => "from the policy file's prices".into(),
        "builtin" => "from Enterplace's own table".into(),
        "litellm" => "from the LiteLLM table".into(),
        _ => "none: cost unknown".into(),
    }
}

// ---- First run ----

pub(crate) fn setup_shell(title: &str, inner: &str) -> String {
    document(
        title,
        &format!(
            r#"<div class="g-shell"><main class="g-shell__main"><div class="g-stack g-measure" style="gap: var(--space-8); padding: var(--space-10)">
<a class="g-nav__brand" href="/console/sign-in" style="padding: 0"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Enterplace</span></a>
{inner}</div></main></div>"#
        ),
    )
}

/// A setup link that is closed, or a setup that could not be done.
pub fn setup_message(title: &str, text: &str) -> String {
    setup_shell(
        title,
        &format!(
            r#"<h1 class="t-lg" style="margin: 0">{}</h1><p class="t-lead g-muted" style="margin: 0">{}</p>"#,
            esc(title),
            esc(text)
        ),
    )
}

/// Step 1 of 4: who the first admin is.
pub fn setup_form(token: &str, error: &str) -> String {
    let error = if error.is_empty() {
        String::new()
    } else {
        alert(error)
    };
    setup_shell(
        "Set up Enterplace",
        &format!(
            r#"<h1 class="t-lg" style="margin: 0">Set up Enterplace</h1>
<p class="t-lead g-muted" style="margin: 0">Step 1 of 4. No one can sign in yet: this link makes the first admin key, once.</p>
{error}<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/setup/{token}">
{name}{team}<div class="g-head__actions">{button}</div></form>"#,
            token = enc(token),
            name = field(&Field {
                id: "name",
                name: "name",
                label: "Your name",
                value: "",
                mono: false,
                extra: r#" required autofocus autocomplete="off""#,
                hint: "As it will appear in the audit log, for example maya.cohen.",
                error: ""
            }),
            team = field(&Field {
                id: "team",
                name: "team",
                label: "Your team",
                value: "",
                mono: false,
                extra: r#" required autocomplete="off""#,
                hint: "Rules can name a team, for example platform.",
                error: ""
            }),
            button = button("Make my admin key", "", "submit", ""),
        ),
    )
}

/// Steps 2 to 4: the key, shown once, how to point a client at Enterplace, and a governed call to try.
/// The prompt for a coding agent (Claude Code, Cursor, Codex) inside a project: find every model call and point it at
/// Enterplace. It names the gateway and the models, never a key. The same text as the Enterplace app's Connect page and the
/// docs' "Connect a project".
pub fn agent_prompt(origin: &str, models: &[String]) -> String {
    let base = origin.trim_end_matches('/');
    let list = if models.is_empty() {
        "(none yet: ask your Enterplace admin which models your rule allows)".to_string()
    } else {
        models.join(", ")
    };
    let first = models.first().map_or("<model>", String::as_str);
    format!(
        "Connect this project to Enterplace, our AI gateway, so every LLM call goes through it.

Enterplace gateway: {base}
OpenAI-compatible base URL: {base}/v1
Anthropic base URL: {base}
The API key is in the environment variable ENTERPLACE_API_KEY. Never write a key into a file that is committed.
Models this project may use through Enterplace: {list}

Do this:
1. Find every place this project calls a model provider: the OpenAI, Anthropic, Azure OpenAI, Google Gemini or Bedrock SDKs, LangChain, LlamaIndex, the Vercel AI SDK, LiteLLM, raw HTTP calls to api.openai.com or api.anthropic.com, and their config and environment files. List them before changing anything.
2. Point each one at Enterplace:
   - OpenAI SDKs and OpenAI-compatible clients: base URL {base}/v1, API key from ENTERPLACE_API_KEY.
   - Anthropic SDKs: base URL {base}, API key from ENTERPLACE_API_KEY.
   - Where a client reads its base URL from the environment (OPENAI_BASE_URL, ANTHROPIC_BASE_URL), prefer setting it there over code changes.
   - Azure OpenAI, Gemini and Bedrock clients: switch them to the OpenAI-compatible client against {base}/v1 with a model from the list above, keeping the same prompts and parameters.
3. Use only the models listed above. Where the code names another model, replace it with the closest one from the list and tell me each replacement.
4. Remove provider keys (OPENAI_API_KEY, ANTHROPIC_API_KEY and the like) from code and committed files. Add ENTERPLACE_API_KEY to .env.example or the project's equivalent, with no value.
5. Do not change prompts, retries, streaming or anything else about how the calls behave.
6. Run the project's tests and build. Then show me the diff and a short list: each call site changed, each model replaced, and any call you could not move and why.

To try one call by hand after the change:
curl {base}/v1/chat/completions -H \"Authorization: Bearer $ENTERPLACE_API_KEY\" -H \"Content-Type: application/json\" -d '{{\"model\":\"{first}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}]}}'"
    )
}

pub fn setup_result(key: &str, origin: &str, models: &[String]) -> String {
    let model = models.first().map_or("<model>", String::as_str);
    let block = |lines: &str| {
        format!(
            r#"<pre class="g-code t-mono" style="white-space: pre-wrap; margin: 0">{}</pre>"#,
            esc(lines)
        )
    };
    setup_shell(
        "Enterplace is set up",
        &format!(
            r#"<h1 class="t-lg" style="margin: 0">Enterplace is set up</h1>
<h2 class="t-sm" style="margin: 0">Step 2 of 4. Your admin key</h2>
<p class="g-muted" style="margin: 0">Shown once. Only its hash is kept, in the keys file. It signs in to the console and makes requests.</p>
{key}
<h2 class="t-sm" style="margin: 0">Step 3 of 4. Point your tools at Enterplace</h2>
{env}
<h2 class="t-sm" style="margin: 0">Step 4 of 4. Make a governed call</h2>
{curl}
<h2 class="t-sm" style="margin: 0">Then: connect a project</h2>
<p class="g-muted" style="margin: 0">Paste this into your coding agent (Claude Code, Cursor, Codex) inside a project. It moves the project's model calls to Enterplace. It holds no key: set ENTERPLACE_API_KEY where the project runs.</p>
<pre id="agent-prompt" class="g-code t-mono" style="white-space: pre-wrap; margin: 0">{prompt}</pre>
<div class="g-head__actions"><button class="g-btn" type="button" data-copy="agent-prompt">Copy for your agent</button></div>
<p style="margin: 0"><a href="/console/sign-in">Sign in to the console</a> with the key to see the call in the audit log and issue keys for your team under People.</p>"#,
            prompt = esc(&agent_prompt(origin, models)),
            key = block(key),
            env = block(&format!(
                "# Claude Code\nexport ANTHROPIC_BASE_URL={origin}\nexport ANTHROPIC_API_KEY={key}\n\n# OpenAI SDKs and Codex\nexport OPENAI_BASE_URL={origin}/v1\nexport OPENAI_API_KEY={key}"
            )),
            curl = block(&format!(
                "curl {origin}/v1/chat/completions \\\n  -H \"Authorization: Bearer {key}\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{{\"model\":\"{model}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}]}}'"
            )),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_times_read_as_the_designs_write_them() {
        let t = "2026-11-13T01:03:03.467Z";
        assert_eq!(time_full(t), "13 Nov 2026, 01:03:03.467 UTC");
        assert_eq!(time_full("garbled"), "garbled");
        assert_eq!(today().len(), 10);
        assert_eq!(day_words("2026-11-01", false), "1 November 2026");
        assert_eq!(day_words("2027-03-31T18:00:00Z", true), "31 Mar");
    }

    #[test]
    fn with_single_sign_on_on_its_button_comes_before_the_key_form() {
        let page = sign_in("", "", true);
        let sso = page
            .find("Sign in with single sign-on")
            .unwrap_or(usize::MAX);
        let or_key = page.find("Or paste an admin key").unwrap_or(0);
        let key = page.find(r#"name="key""#).unwrap_or(0);
        assert!(sso < or_key && or_key < key, "{page}");
        assert!(!sign_in("", "", false).contains("Or paste an admin key"));
    }

    #[test]
    fn a_diff_shows_the_removed_line_before_the_added_one() {
        let kinds: Vec<&str> = diff("a\nb\nc\n", "a\nB\nc\n")
            .into_iter()
            .map(|(_, _, kind)| kind)
            .collect();
        assert_eq!(kinds, ["", "del", "add", ""]);
    }
}
