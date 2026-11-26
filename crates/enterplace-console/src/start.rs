//! The setup checklists in the console app (`/console/app/#/overview`, and each use case's page): the first-run welcome, the checklist of
//! the starting choice with live done detection, the first requests, and the five steps once the choice is set up.
//! The API computes every step and its words; the app lays them out and polls, so a step turns done as the gateway
//! sees it happen.
//!
//! Every step's state is computed from the gateway's real records: keys, the request log, the policy and, through
//! the extension, watch mode. Nothing is ticked by hand. The starting choice is kept in the store when there is one,
//! else in `enterplace-start.json` beside the audit log.

use std::fmt::Write as _;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use enterplace_core::{
    config::{self, KeyEntry},
    insights::{Query, Row},
    keyfile,
    policy::{Mode, Permission, ScopeKind},
    store,
};
use serde_json::{Map, Value, json};

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED, Tls,
    api::{Fail, answer, bad, body_of, ok, signed_in, text},
    edit,
    figures::{money, money_est, time_list},
    html::{code, empty, enc, esc, icon, motif},
    insights, pages, read_only, record, redirect, secure,
};

/// The docs site every step links into.
pub(crate) const DOCS: &str = "https://docs.enterplace.dev";

// ---------------------------------------------------------------- the five starting choices

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Track {
    Coding,
    Apps,
    Mcp,
    Limit,
    Watch,
}

const TRACKS: [Track; 5] = [
    Track::Coding,
    Track::Apps,
    Track::Mcp,
    Track::Limit,
    Track::Watch,
];

impl Track {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Track::Coding => "coding",
            Track::Apps => "apps",
            Track::Mcp => "mcp",
            Track::Limit => "limit",
            Track::Watch => "watch",
        }
    }

    fn of(id: &str) -> Option<Track> {
        TRACKS.into_iter().find(|t| t.id() == id)
    }

    fn name(self) -> &'static str {
        match self {
            Track::Coding => "Coding agents",
            Track::Apps => "Our own apps and agents",
            Track::Mcp => "MCP tools",
            Track::Limit => "A spend limit for the team",
            Track::Watch => "Claude Team seats we can only watch",
        }
    }

    /// The track as the toast after picking it names it: lower case, so it reads inside a sentence.
    fn steps_for(self) -> &'static str {
        match self {
            Track::Coding => "coding agents",
            Track::Apps => "your own apps and agents",
            Track::Mcp => "MCP tools",
            Track::Limit => "a team spend limit",
            Track::Watch => "watching Claude Team seats",
        }
    }

    fn button(self) -> &'static str {
        match self {
            Track::Coding => "coding agents",
            Track::Apps => "our apps",
            Track::Mcp => "MCP tools",
            Track::Limit => "a spend limit",
            Track::Watch => "watching Claude Team",
        }
    }

    fn line(self) -> &'static str {
        match self {
            Track::Coding => {
                "Codex, Claude Code, Cursor, Gemini CLI and the other coding agents your developers use."
            }
            Track::Apps => {
                "Services, scripts and agents in your code that call OpenAI, Anthropic or Gemini."
            }
            Track::Mcp => {
                "Put MCP servers behind Enterplace and pick which tools wait for an admin's approval."
            }
            Track::Limit => {
                "Cap what each team spends in a month, after a look at what it spends now."
            }
            Track::Watch => {
                "See who uses Claude Code on Claude Team or Enterprise seats and what it costs. Nothing is routed."
            }
        }
    }

    fn covers(self) -> &'static str {
        match self {
            Track::Coding => "See, and Know for the people you add",
            Track::Apps => "See, for workloads",
            Track::Mcp => "Protect, for tools",
            Track::Limit => "See, then Limit",
            Track::Watch => "See and Know, on the watch track",
        }
    }

    fn enterprise(self) -> bool {
        self == Track::Watch
    }

    /// Connect a model and Send your first request come first on every track but Watch, which has no model to connect.
    fn steps(self) -> usize {
        match self {
            Track::Watch => 4,
            // Claude subscriptions, the default way to pay: no model to connect and no first request with a key.
            Track::Coding => 4,
            Track::Limit => 6,
            _ => 5,
        }
    }
}

// ---------------------------------------------------------------- what is kept

/// The starting choice, whether the welcome was skipped, and whether the five steps were asked for.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Kept {
    pub choice: Option<Track>,
    pub skipped: bool,
    pub steps: bool,
    /// The person chose the demo model over connecting a provider for now.
    pub demo: bool,
}

const SETTING: &str = "start";

fn kept_file(console: &Console) -> std::path::PathBuf {
    let audit = &console.config().audit;
    audit.parent().map_or_else(
        || "enterplace-start.json".into(),
        |d| d.join("enterplace-start.json"),
    )
}

fn kept_store(console: &Console) -> Option<std::sync::Arc<dyn store::Store>> {
    store::attached(&console.config().keys).filter(|s| s.keeps_settings())
}

pub(crate) fn read_kept(console: &Console) -> Result<Kept, String> {
    let text = match kept_store(console) {
        Some(s) => s.setting(SETTING)?,
        None => match std::fs::read_to_string(kept_file(console)) {
            Ok(text) => Some(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(format!(
                    "{} cannot be read ({err}). Give Enterplace read access to it.",
                    kept_file(console).display()
                ));
            }
        },
    };
    let value: Value = text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok())
        .unwrap_or(Value::Null);
    Ok(Kept {
        choice: value["choice"].as_str().and_then(Track::of),
        skipped: value["skipped"].as_bool().unwrap_or(false),
        steps: value["steps"].as_bool().unwrap_or(false),
        demo: value["demo"].as_bool().unwrap_or(false),
    })
}

fn write_kept(console: &Console, kept: &Kept) -> Result<(), String> {
    let text = json!({
        "choice": kept.choice.map(Track::id),
        "skipped": kept.skipped,
        "steps": kept.steps,
        "demo": kept.demo,
    })
    .to_string();
    if let Some(s) = kept_store(console) {
        return s.set_setting(SETTING, &text);
    }
    let path = kept_file(console);
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, &text)
        .and_then(|()| std::fs::rename(&temp, &path))
        .map_err(|err| {
            format!(
                "{} cannot be written ({err}). Give Enterplace write access to the audit log's folder.",
                path.display()
            )
        })
}

// ---------------------------------------------------------------- the facts every step is computed from

#[derive(Default)]
pub(crate) struct Facts {
    /// The gateway's address as the browser reached it.
    pub base: String,
    pub observe: bool,
    /// The policy is kept in the store, so a policy line can open a draft.
    pub draft: bool,
    pub policy_path: String,
    /// The keys file `enterplace key new` writes to, named in agent prompts so the command works from any folder.
    pub keys_path: String,
    /// Keys that are not admin keys, within the person's reach, in file order.
    pub people: Vec<KeyEntry>,
    /// The first 8 characters of each admin key's hash, as requests record their key.
    pub admin_keys: Vec<String>,
    /// Model requests with a person, newest first.
    pub requests: Vec<Row>,
    /// MCP tool calls, newest first.
    pub tool_calls: Vec<Row>,
    /// MCP calls that waited for an admin's approval and were answered.
    pub approvals: usize,
    /// Requests a watched coding tool reported, newest first.
    pub watched: Vec<Row>,
    pub mcp_servers: Vec<String>,
    /// Scope limits with a budget, as (kind, name).
    pub budgets: Vec<(String, String)>,
    pub rule_budgets: bool,
    pub guarded: bool,
    pub self_issue: bool,
    pub watch_on: bool,
    pub watch_tokens: usize,
    pub verified: bool,
    /// What could not be read, said on the page.
    pub problem: String,
    /// Providers in the policy other than the demo model, in file order, with their first model.
    pub connected: Vec<(String, String)>,
    /// The demo model is in the policy.
    pub demo_in_policy: bool,
    /// The person chose to try the demo model first.
    pub demo: bool,
    /// Every model request with a key, answered or refused, newest first: the first request step counts these.
    pub tries: Vec<Row>,
    /// Provider keys can be pasted here: a store or the sealed file keeps them.
    pub credentials_on: bool,
    /// A provider sends Claude Code's own subscription logins on (`auth: passthrough`).
    pub passthrough: bool,
    /// That provider takes a request with no person token (`identity: optional`), recorded as the person unknown.
    pub unnamed_ok: bool,
}

impl Facts {
    fn names(&self) -> Vec<&str> {
        self.people.iter().map(|k| k.name.as_str()).collect()
    }

    /// Requests sent with a key other than an admin's. The admin key carries its holder's name, so a test call with it
    /// shares a name with their person token: the key, not the name, tells them apart.
    fn sent_by_people(&self) -> Vec<&Row> {
        let names = self.names();
        self.requests
            .iter()
            .filter(|r| {
                names.contains(&r.label("person"))
                    && !self.admin_keys.iter().any(|k| k == r.label("key"))
            })
            .collect()
    }

    fn senders(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .sent_by_people()
            .iter()
            .map(|r| r.label("person").to_string())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Requests sent with a person's own Claude subscription login, by a person Enterplace knows.
    fn subscribed(&self) -> Vec<&Row> {
        self.sent_by_people()
            .into_iter()
            .filter(|r| r.estimate)
            .collect()
    }

    fn subscribers(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .subscribed()
            .iter()
            .map(|r| r.label("person").to_string())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn newest(&self, workload: bool) -> Option<&KeyEntry> {
        self.people.iter().rev().find(|k| {
            workload == (k.options.metadata.get("kind").map(String::as_str) == Some("workload"))
        })
    }

    fn budget_for(&self, team: &str) -> bool {
        self.budgets
            .iter()
            .any(|(k, n)| k == "global" || (k == "team" && (n == team || n == "*")))
    }

    /// The teams with traffic in the last 7 days, and those of them no budget caps yet.
    fn teams_capped(&self) -> (Vec<&str>, Vec<&str>) {
        let week = enterplace_core::insights::now_secs().saturating_sub(7 * 86_400);
        let mut teams: Vec<&str> = self
            .requests
            .iter()
            .filter(|r| enterplace_core::insights::unix_secs(&r.time).is_some_and(|t| t >= week))
            .map(|r| r.label("team"))
            .filter(|t| !t.is_empty())
            .collect();
        teams.sort_unstable();
        teams.dedup();
        let open = teams
            .iter()
            .copied()
            .filter(|t| !self.budget_for(t))
            .collect();
        (teams, open)
    }

    /// Add a limit on Rules and limits, for the first team with traffic and no budget.
    fn add_budget_href(&self) -> String {
        let (_, open) = self.teams_capped();
        match open.first() {
            Some(team) => format!(
                "/console/app/#/policy?add=limit&team={}",
                crate::html::enc(team)
            ),
            None => "/console/app/#/policy?add=limit".into(),
        }
    }
}

pub fn origin(headers: &HeaderMap, uri: &Uri, tls: &Tls) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("127.0.0.1:8080");
    let scheme = if secure(headers, uri, tls) {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

pub(crate) async fn facts(console: &Console, admin: &Admin, base: String) -> Facts {
    let c = console.config();
    let mut f = Facts {
        base,
        policy_path: c.policy.display().to_string(),
        keys_path: c.keys.display().to_string(),
        draft: edit::live(console).is_some(),
        watch_on: console.0.watch.is_some(),
        verified: console
            .verified(admin.org.as_deref().unwrap_or(""))
            .is_some_and(|(_, r)| r.is_ok()),
        ..Facts::default()
    };
    f.credentials_on = store::credentials_for(&c.keys).is_some();
    f.demo = read_kept(console).is_ok_and(|k| k.demo);
    if let Ok(loaded) = config::load(&c.policy, Some(&c.keys)) {
        f.observe = loaded.policy.mode() == Mode::Observe;
        for p in &loaded.providers {
            if p.passthrough {
                // Not a connected model: it holds no key, and a first request with an Enterplace key cannot use it.
                f.passthrough = true;
                f.unnamed_ok |= p.identity_optional;
            } else if p.kind == config::Kind::Demo {
                f.demo_in_policy = true;
            } else {
                f.connected.push((
                    p.name.clone(),
                    p.models.first().cloned().unwrap_or_default(),
                ));
            }
        }
        f.mcp_servers = loaded.mcp.iter().map(|s| s.name.clone()).collect();
        f.budgets = loaded
            .policy
            .scope_limits()
            .iter()
            .filter(|l| !l.budgets.is_empty())
            .map(|l| {
                let kind = if l.kind == ScopeKind::Global {
                    "global"
                } else {
                    l.kind.word()
                };
                (kind.to_string(), l.name.clone())
            })
            .collect();
        f.rule_budgets = loaded
            .policy
            .rule_list()
            .iter()
            .any(|r| !r.limits.budgets.is_empty());
        // A team's own rule with a budget caps that team as a limits: entry does.
        for r in loaded.policy.rule_list() {
            if let enterplace_core::policy::Who::Team(team) = &r.who
                && !r.limits.budgets.is_empty()
            {
                f.budgets.push(("team".into(), team.clone()));
            }
        }
        f.guarded = loaded
            .policy
            .rule_list()
            .iter()
            .any(|r| !r.guardrails.is_empty());
        f.self_issue = loaded.sso.as_ref().is_some_and(|s| s.self_issue.is_some())
            || loaded.saml.as_ref().is_some_and(|s| s.self_issue.is_some());
    }
    let text = store::attached(&c.keys)
        .map(|s| s.keys_text())
        .or_else(|| config::read_keys(&c.keys).ok().flatten())
        .unwrap_or_default();
    let entries = config::key_entries(&c.keys, &text).unwrap_or_default();
    f.admin_keys = entries
        .iter()
        .filter(|k| k.admin)
        .filter_map(|k| k.sha256.get(..8).map(str::to_string))
        .collect();
    f.people = entries
        .into_iter()
        // The key Send your first request makes is no person's or app's: it does not tick their steps.
        .filter(|k| !k.admin && admin.covers_entry(k) && !first_request_key(k))
        .collect();
    // ponytail: the newest 5,000 rows are read on every load and every poll; the store's index answers that in SQL,
    // the local chain is folded whole. A count query per fact comes when logs grow large.
    let mut query = Query {
        limit: 5000,
        ..Query::default()
    };
    insights::scoped(admin, &mut query);
    match insights::rows(console, &query).await {
        Ok(rows) => {
            for row in rows {
                if row.label("source") == "watch" {
                    f.watched.push(row);
                } else if row.path.starts_with("/mcp") {
                    if row.line.contains("\"approved_by\"") || row.code.starts_with("approval_") {
                        f.approvals += 1;
                    }
                    if row.line.contains("\"tools/call\"") {
                        f.tool_calls.push(row);
                    }
                } else if !row.label("person").is_empty()
                    && row.path.starts_with("/v1")
                    && !row.path.ends_with("/models")
                {
                    if row.verdict != "refused" {
                        f.requests.push(row.clone());
                    }
                    f.tries.push(row);
                }
            }
        }
        Err(err) => {
            f.problem = format!("The request log could not be read: {err}");
        }
    }
    if let Some(watch) = &console.0.watch {
        f.watch_tokens = (watch.tokens)(admin.clone()).await.unwrap_or(0);
    }
    f
}

// ---------------------------------------------------------------- policy lines

/// A change to the policy text that a step proposes.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Change {
    /// Items under a top-level list, which is added when missing.
    List(&'static str, Vec<String>),
    /// A server under `mcp:`, and the tools it serves allowed in the first rule.
    Server(Vec<String>, String),
    /// Lines in the rule that allows tools, or in the first rule.
    InRule(Vec<String>),
    /// A line taken out.
    Remove(&'static str),
}

/// The change a policy line of Start here stands for, by the name its link carries.
pub(crate) fn change(name: &str) -> Option<Change> {
    if let Some(team) = name.strip_prefix("budget-team:") {
        return config::valid_name(team).then(|| {
            Change::List(
                "limits",
                vec![format!(
                    "  - {{ team: {team}, budget: {{ usd: 200, per: month }} }}"
                )],
            )
        });
    }
    Some(match name {
        "budget-all" => Change::List(
            "limits",
            vec![r#"  - { team: "*", budget: { usd: 500, per: month } }"#.into()],
        ),
        "mcp-server" => Change::Server(
            vec![
                "  - name: github".into(),
                "    url: https://api.githubcopilot.com/mcp".into(),
                "    headers_env: { Authorization: GITHUB_MCP_AUTHORIZATION }".into(),
            ],
            "    tools: [github.*]".into(),
        ),
        "approve" => Change::InRule(vec![
            "    approve_tools: [github.merge_pull_request]".into(),
            "    approval_timeout_seconds: 120".into(),
        ]),
        "enforce" => Change::Remove("mode: observe"),
        _ => return None,
    })
}

/// The end of the first rule's lines: the index after its last line.
fn first_rule_end(lines: &[String]) -> Option<usize> {
    let rules = lines.iter().position(|l| l.trim_end() == "rules:")?;
    let first = (rules + 1..lines.len()).find(|&i| lines[i].starts_with("  - "))?;
    Some(
        (first + 1..lines.len())
            .find(|&i| {
                let l = &lines[i];
                l.starts_with("  - ")
                    || (!l.is_empty() && !l.starts_with(' ') && !l.starts_with('#'))
            })
            .unwrap_or(lines.len()),
    )
}

/// The policy text with the change made, and the changed lines as the code block marks them (number, text, kind).
pub(crate) fn apply(text: &str, change: &Change) -> (String, Vec<(usize, String, &'static str)>) {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut marks = Vec::new();
    let insert = |lines: &mut Vec<String>, at: usize, new: &[String], marks: &mut Vec<_>| {
        for (j, l) in new.iter().enumerate() {
            lines.insert(at + j, l.clone());
            marks.push((at + j + 1, l.clone(), "add"));
        }
    };
    let list = |lines: &mut Vec<String>, key: &str, items: &[String], marks: &mut Vec<_>| {
        let head = format!("{key}:");
        match lines.iter().position(|l| l.trim_end() == head) {
            Some(i) => insert(lines, i + 1, items, marks),
            None => {
                let at = lines.len();
                let mut new = vec![head];
                new.extend(items.iter().cloned());
                insert(lines, at, &new, marks);
            }
        }
    };
    match change {
        Change::List(key, items) => list(&mut lines, key, items, &mut marks),
        Change::Server(server, tools) => {
            list(&mut lines, "mcp", server, &mut marks);
            if let Some(end) = first_rule_end(&lines) {
                insert(&mut lines, end, std::slice::from_ref(tools), &mut marks);
            }
        }
        Change::InRule(new) => {
            let at = lines
                .iter()
                .position(|l| l.starts_with("    tools:"))
                .map(|i| i + 1)
                .or_else(|| first_rule_end(&lines));
            if let Some(at) = at {
                insert(&mut lines, at, new, &mut marks);
            }
        }
        Change::Remove(line) => {
            if let Some(i) = lines.iter().position(|l| l.trim_end() == *line) {
                lines.remove(i);
                marks.push((i + 1, (*line).to_string(), "del"));
            }
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    (out, marks)
}

fn policy_text(console: &Console) -> String {
    config::policy_text(&console.config().policy).unwrap_or_default()
}

// ---------------------------------------------------------------- the server-rendered empty states' builders

fn copy_button(id: &str) -> String {
    format!(
        r#"<button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="{id}">{}Copy</button>"#,
        icon("copy")
    )
}

fn docs(label: &str, path: &str) -> String {
    format!(r#"<a class="g-link t-small" href="{DOCS}{path}">{label}</a>"#)
}

fn acts(inner: &str) -> String {
    format!(r#"<div class="g-setup__actions">{inner}</div>"#)
}

/// One command, in the Command component with Copy.
fn command(id: &str, text: &str) -> String {
    format!(
        r#"<span class="g-command"><span class="g-command__text t-mono" id="{id}">{}</span>{}</span>"#,
        esc(text),
        copy_button(id)
    )
}

// ---------------------------------------------------------------- the blocks the app lays out

/// Inline text the app shows: a value between backticks is set in mono, and `[label](href)` is a link.
fn mono(text: &str) -> String {
    format!("`{text}`")
}

fn clock(time: &str) -> String {
    format!("{} UTC", time_list(time))
}

fn p(text: impl Into<String>) -> Value {
    json!({ "type": "p", "text": text.into() })
}

/// A small muted line under what it is about.
fn note(text: impl Into<String>) -> Value {
    json!({ "type": "note", "text": text.into() })
}

fn link(label: &str, href: &str) -> Value {
    json!({ "type": "link", "label": label, "href": href })
}

fn docs_link(label: &str, path: &str) -> Value {
    link(label, &format!("{DOCS}{path}"))
}

/// Buttons and links on one row. Nothing when there is none.
fn actions(items: Vec<Value>) -> Value {
    if items.is_empty() {
        Value::Null
    } else {
        json!({ "type": "actions", "items": items })
    }
}

/// A button that posts `body` to `/console/api/start/<action>`.
fn button(label: &str, action: &str, body: Value, quiet: bool) -> Value {
    json!({ "type": "button", "label": label, "action": action, "body": body, "quiet": quiet })
}

fn command_block(text: &str) -> Value {
    json!({ "type": "command", "text": text })
}

/// Tabs that pick which lines a step shows, by one value of the app route's query; `keep` is set along with it, so
/// a tab keeps an answer such as how the team pays.
fn tabs(param: &str, label: &str, options: &[(&str, &str)], selected: &str, keep: Value) -> Value {
    json!({
        "param": param,
        "label": label,
        "options": options.iter().map(|(id, l)| json!({ "id": id, "label": l })).collect::<Vec<_>>(),
        "selected": selected,
        "keep": keep,
    })
}

/// Lines to paste, with Copy. `id` names them for the browser checks.
fn lines_block(id: &str, tabs: Value, caption: &str, lines: &[String]) -> Value {
    json!({ "type": "lines", "id": id, "tabs": tabs, "caption": caption, "lines": lines })
}

fn input(name: &str, label: &str, placeholder: &str) -> Value {
    json!({ "name": name, "label": label, "placeholder": placeholder })
}

/// A form that posts its fields and `hidden` to `/console/api/start/<action>`.
fn form(action: &str, button: &str, hidden: Value, fields: Vec<Value>) -> Value {
    json!({ "type": "form", "action": action, "button": button, "hidden": hidden, "fields": fields, "after": "" })
}

// ---------------------------------------------------------------- the steps

pub(crate) struct Step {
    title: String,
    optional: bool,
    done: bool,
    /// Enterplace watches the request log for it, so it listens while it is the current step.
    listens: bool,
    now: Vec<Value>,
    listen: String,
    done_text: String,
    open: Option<(&'static str, &'static str)>,
    /// What "Copy for your agent" copies: the step as a prompt for any coding agent.
    agent: String,
}

/// A step as a prompt for the person's coding agent: the goal, the exact values, what to run or change, how to tell it
/// worked, and the docs page as Markdown for anything else. Never an admin key: only what the step already shows.
fn prompt(
    base: &str,
    goal: &str,
    values: &[(&str, String)],
    todo: &[String],
    verify: &str,
    doc: &str,
) -> String {
    task_prompt(
        base,
        goal,
        values,
        todo,
        &format!(
            "{verify} The step on {base}/console/start turns done by itself; requests show at {base}/console/requests."
        ),
        doc,
    )
}

/// An agent prompt for a task outside Start here: the same parts, with a check of the task's own.
pub fn task_prompt(
    base: &str,
    goal: &str,
    values: &[(&str, String)],
    todo: &[String],
    verify: &str,
    doc: &str,
) -> String {
    let mut out = format!(
        "Goal: {goal}, for the Enterplace AI gateway at {base}.\n\nValues:\n- Enterplace URL: {base}\n"
    );
    for (name, value) in values {
        let _ = writeln!(out, "- {name}: {value}");
    }
    out.push_str("\nDo this:\n");
    for line in todo {
        let _ = writeln!(out, "{line}");
    }
    let _ = write!(
        out,
        "\nVerify: {verify}\n\nDocs (Markdown, read it for anything not covered here): {}\n\nDo not print, log or commit any key or token other than the values above, and ask me before changing anything else.\n",
        md(doc)
    );
    out
}

/// "Copy for your agent" on Guardrails: the policy lines of a guardrail and the check, so an agent adds one alone.
pub(crate) fn guardrail_prompt(base: &str, policy: &str, in_store: bool) -> String {
    let (file, save) = if in_store {
        (
            format!(
                "a copy of {policy} (this policy is kept in the store, so the file itself is not read)"
            ),
            format!(
                "Paste the new lines into the policy editor at {base}/console/app/#/policy/edit, check the change and its dry run, and apply it."
            ),
        )
    } else {
        (
            policy.to_string(),
            "Save the file. The gateway reads it within 2 seconds of a save that passes the check."
                .into(),
        )
    };
    let checked = if in_store {
        "<path of the copy>"
    } else {
        policy
    };
    task_prompt(
        base,
        "Add a guardrail to the Enterplace policy",
        &[("Policy file", policy.to_string())],
        &[
            "1. Ask me, if I have not said them: what to catch (secrets, pii, regex with its patterns, or keywords with their words), whether to block, mask or warn, and whether to try it first until a date.".into(),
            format!("2. Edit {file}: under `guardrails:` add an entry like this one (a name of your choosing, the type and action I picked; leave out shadow_until to act now):"),
            "```yaml\nguardrails:\n  - name: no-secrets\n    type: secrets\n    action: block\n    on: [request, answer]\n    shadow_until: 2026-12-31   # until this UTC day it records what it would do and blocks nothing\ndefault_guardrails: [no-secrets]   # runs on every request; or name it under a rule's guardrails:\n```".into(),
            format!("3. Run `enterplace check {checked}` and fix every problem it names, by its line, until it passes."),
            format!("4. {save}"),
        ],
        &format!(
            "`enterplace check` passes, and the guardrail is listed at {base}/console/app/#/policy. Its Test button there runs it on a sample; hits show in the Audit log as Blocked, Masked, Warned or Would block."
        ),
        "/governance/guardrails/",
    )
}

/// "Copy for your agent" on Limits: budgets and token rates per team or person, as policy lines, and the check.
pub(crate) fn limit_prompt(base: &str, policy: &str, in_store: bool) -> String {
    let save = if in_store {
        format!(
            "This policy is kept in the store, so the file is not read: paste the lines into the policy editor at {base}/console/app/#/policy/edit, press Dry run, and save."
        )
    } else {
        "Save the file; the gateway reads it within 2 seconds of a save that passes the check."
            .into()
    };
    task_prompt(
        base,
        "Set budgets and token limits per team and per person in Enterplace",
        &[("Policy file", policy.to_string())],
        &[
            "1. Ask me, if I have not said them: which teams and people, and for each a budget in US dollars (per day, week or month) and tokens per day.".into(),
            "2. Under `limits:` in the policy, add one entry per team or person, like these:".into(),
            "```yaml\nlimits:\n  - team: payments\n    budget: { usd: 500, per: month }\n    rate: { tpd: 2000000 }\n  - person: maya.cohen\n    rate: { tpd: 300000 }\n  - team: \"*\"   # the same cap for each team on its own\n    budget: { usd: 200, per: month }\n```".into(),
            format!("3. Run `enterplace check {policy}` and fix every problem it names. {save}"),
        ],
        &format!(
            "The limits show under Limits at {base}/console/app/#/policy and in each team's row at {base}/console/app/#/teams. A request over one is refused, and Requests names the limit: Refused: rate limited, team payments tokens per day."
        ),
        "/governance/budgets-and-rate-limits/",
    )
}

/// "Copy for your agent" on Rules: who may use which models, one rule per team or person, before the one for everyone.
pub(crate) fn rule_prompt(base: &str, policy: &str, in_store: bool) -> String {
    task_prompt(
        base,
        "Add rules for who may use which models in Enterplace",
        &[("Policy file", policy.to_string())],
        &[
            "1. Ask me, if I have not said them: which teams or people, and the models each may use (`*` for every model).".into(),
            "2. Under `rules:` in the policy, add one rule per team or person, before the rule for everyone: the first rule that matches a caller decides. Like these:".into(),
            "```yaml\nrules:\n  - name: payments-team\n    principals: { team: payments }\n    models: [claude-sonnet-5-5, claude-haiku-5-5]\n  - name: maya-only\n    principals: { name: maya.cohen }\n    models: [\"*\"]\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n```".into(),
            format!("3. Run `enterplace check {policy}` and fix every problem it names. {}", save_line(base, in_store)),
        ],
        &format!(
            "The rules show under Rules at {base}/console/app/#/policy. A request from a team or person for a model its rule does not allow is refused, and Requests names the rule."
        ),
        "/governance/policy/",
    )
}

/// "Copy for your agent" on Aliases: one model name callers send, spread over providers, with fallbacks.
pub(crate) fn alias_prompt(base: &str, policy: &str, in_store: bool) -> String {
    task_prompt(
        base,
        "Add a model alias with fallbacks in Enterplace",
        &[("Policy file", policy.to_string())],
        &[
            "1. Ask me, if I have not said them: the name callers will send, the provider and model behind it, and what to fall back to.".into(),
            "2. Under `aliases:` in the policy, add the alias, and name it in the `models:` of each rule that may use it. Like this:".into(),
            "```yaml\naliases:\n  - name: smart\n    deployments:\n      - { provider: anthropic, model: claude-sonnet-5-5 }\n    fallbacks: [claude-haiku-5-5]\n```".into(),
            format!("3. Run `enterplace check {policy}` and fix every problem it names. {}", save_line(base, in_store)),
        ],
        &format!(
            "The alias shows under Aliases and fallbacks at {base}/console/app/#/policy. Send one request with the alias as the model and check Requests at {base}/console/app/#/requests names the model it went to."
        ),
        "/routing/aliases/",
    )
}

/// "Copy for your agent" on MCP servers: a server's lines, its header kept in an environment variable the human sets,
/// and the check. Never the token itself.
pub(crate) fn mcp_prompt(base: &str, policy: &str, in_store: bool) -> String {
    task_prompt(
        base,
        "Add an MCP server behind the Enterplace MCP gateway",
        &[("Policy file", policy.to_string()), ("MCP gateway", format!("{base}/mcp"))],
        &[
            "1. Ask me, if I have not said them: the server's name and URL, and the header it needs, if any. Do not ask me for the token: I set it myself.".into(),
            "2. Under `mcp:` in the policy, add the server, with its header read from an environment variable, and give the rules that may use it `tools:`. Like this:".into(),
            "```yaml\nmcp:\n  - name: github\n    url: https://api.githubcopilot.com/mcp\n    headers_env: { Authorization: GITHUB_MCP_AUTHORIZATION }\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n    tools: [github.*]\n```".into(),
            "3. Tell me the environment variable to set where the gateway runs (GITHUB_MCP_AUTHORIZATION above), and wait until I say it is set.".into(),
            format!("4. Run `enterplace check {policy}` and fix every problem it names. {}", save_line(base, in_store)),
        ],
        &format!(
            "The server shows at {base}/console/app/#/mcp with its tools under Tools. Point your MCP client at {base}/mcp with your Enterplace key and list the tools."
        ),
        "/governance/mcp-gateway/",
    )
}

/// How a policy change is saved, for an agent prompt: the editor when the policy is kept in the store, else the file.
fn save_line(base: &str, in_store: bool) -> String {
    if in_store {
        format!(
            "This policy is kept in the store, so the file is not read: paste the lines into the policy editor at {base}/console/app/#/policy/edit, press Dry run, and save, after the check passes on a copy of the file with them."
        )
    } else {
        "Save the file; the gateway reads it within 2 seconds of a save that passes the check, and keeps the version it has if it refuses one.".into()
    }
}

/// "Copy for your agent" on Providers: a provider's policy lines from the catalog, its key in an environment variable
/// the human sets, and the check. Never the key itself.
pub(crate) fn provider_prompt(base: &str, policy: &str, in_store: bool) -> String {
    task_prompt(
        base,
        "Connect a model provider to the Enterplace gateway",
        &[("Policy file", policy.to_string())],
        &[
            "1. Ask me, if I have not said them: which provider (run `enterplace providers` for the catalog ids) and which of its models people may use.".into(),
            "2. Under `providers:` in the policy, add an entry like this one, with the catalog id as `preset` and the models I picked:".into(),
            "```yaml\nproviders:\n  - name: groq\n    preset: groq\n    key_env: GROQ_API_KEY\n    models: [llama-3.3-70b-versatile, llama-3.1-8b-instant]\n```".into(),
            "3. Tell me to set the key variable on every gateway myself (`export GROQ_API_KEY=...` in the gateway's environment, or its secret manager) and restart them, or to paste the key on the Providers page, which seals it. Never ask me to paste the key to you, and never write it in a file.".into(),
            format!("4. Run `enterplace check {policy}` and fix every problem it names. {}", save_line(base, in_store)),
        ],
        &format!(
            "The provider is listed at {base}/console/app/#/providers, the save's message says the gateways run it (not that one refused it), and its Test button on {base}/console/app/#/deployments answers. A request for one of its models through {base}/v1/chat/completions is answered."
        ),
        "/providers/overview/",
    )
}

/// "Copy for your agent" on Prices: a model's price per million tokens in the policy's `prices:`, and the check.
pub(crate) fn price_prompt(base: &str, policy: &str, in_store: bool) -> String {
    task_prompt(
        base,
        "Set the price of a model in the Enterplace policy, so its spend counts against budgets",
        &[("Policy file", policy.to_string())],
        &[
            "1. Ask me, if I have not said them: the model, and its price in US dollars per million input and output tokens (from the provider's pricing page or our contract).".into(),
            "2. Under `prices:` in the policy, add or change its entry:".into(),
            "```yaml\nprices:\n  llama-3.3-70b-versatile: { input: 0.59, output: 0.79 }\n```".into(),
            format!("3. Run `enterplace check {policy}` and fix every problem it names. {}", save_line(base, in_store)),
            format!("4. Run `enterplace prices <model> --policy {policy}` and check it shows the price from the policy."),
        ],
        &format!(
            "The model shows the new price, with the source policy, at {base}/console/app/#/prices, and its next requests are counted at it on {base}/console/app/#/spend."
        ),
        "/governance/budgets-and-rate-limits/",
    )
}

/// "Copy for your agent" where a pasted provider key needs a master key and the gateway has none: make one and set
/// it on every gateway. The key is made and kept by the human's own tools; the agent never sees it.
pub(crate) fn master_key_prompt(base: &str) -> String {
    task_prompt(
        base,
        "Give the Enterplace gateway a master key, so provider keys pasted in the console are kept encrypted",
        &[],
        &[
            "1. Tell me to make the key myself with `openssl rand -hex 32` (64 hex characters) and keep it in our secret manager, or in a file only the gateway's user can read (`chmod 600`). Never ask me to paste it to you, and never write it in the repository.".into(),
            "2. Set `ENTERPLACE_MASTER_KEY` to it, or `ENTERPLACE_MASTER_KEY_FILE` to the path of that file, in the environment of every gateway: its systemd unit, container env, Helm values or task definition. Every gateway must use the same key.".into(),
            "3. Restart each gateway: it reads the master key when it starts.".into(),
        ],
        &format!(
            "Add a provider at {base}/console/app/#/providers asks for the provider's key, and {base}/console/app/#/credentials lists provider keys instead of saying the master key is missing."
        ),
        "/governance/provider-credentials/",
    )
}

/// "Copy for your agent" on Import a list: `enterplace key import` on a CSV, so an agent issues a team's keys alone.
pub(crate) fn import_prompt(base: &str, keys: &str) -> String {
    task_prompt(
        base,
        "Issue Enterplace keys and person tokens for a list of people",
        &[("Keys file", keys.to_string())],
        &[
            "1. Ask me for the list if I have not given it: each person's name and team, and optionally a monthly budget in US dollars and the kind (key, or person for a person token that names someone using their own Claude login).".into(),
            "2. Write it as people.csv, one person per line, with this header:".into(),
            "```csv\nname,team,budget,kind\nana.silva,payments,50,key\nomer.katz,payments,,person\n```".into(),
            format!("3. Run `enterplace key import people.csv --keys {keys}` (add `--policy <policy file>` when the keys are kept in a store). It checks every line first and issues nothing while one is wrong; fix the lines it names and run it again."),
            "4. It writes the keys once, as name,team,key, to the file named by --out (people-keys.csv by default). Do not print, log or commit that file: tell me where it is, so I hand each key over through our secret manager and delete the file.".into(),
        ],
        &format!(
            "Each person is listed at {base}/console/app/#/people with their team, and the audit log at {base}/console/app/#/audit has one import_keys record with the count."
        ),
        "/governance/keys/",
    )
}

/// "Copy for your agent" on Bring everyone in: single sign-on with `enterplace login`, so each developer gets their own
/// key named by their email, and an agent sets it up alone.
pub(crate) fn sign_on_prompt(base: &str, policy: &str, in_store: bool) -> String {
    let save = if in_store {
        format!(
            "This policy is kept in the store, so the file is not read: paste the section into the policy editor at {base}/console/app/#/policy/edit and save, after the check passes on a copy of the file with it."
        )
    } else {
        "Add the section to the policy file; the gateway reads it within 2 seconds of a save that passes the check.".into()
    };
    task_prompt(
        base,
        "Let every developer get their own Enterplace key through single sign-on",
        &[
            ("Policy file", policy.to_string()),
            ("Redirect URL to register", format!("{base}/console/sso/callback")),
        ],
        &[
            "1. Ask me, if I have not said them: the identity provider (Okta, Microsoft Entra ID, Google, Keycloak or any OpenID Connect provider), its issuer URL, the company email domain, the group whose members are console admins, and the team new people go to.".into(),
            "2. Tell me to register Enterplace at the provider as an OpenID Connect web application with the redirect URL above, with `email` and the groups claim in the ID token, and to give you the client ID. I set the client secret myself on every gateway as ENTERPLACE_SSO_SECRET; never ask me to paste it to you.".into(),
            "3. Under `console:` in the policy, add (with my answers):".into(),
            "```yaml\nconsole:\n  sso:\n    issuer: https://login.example.com\n    client_id: enterplace-console\n    client_secret_env: ENTERPLACE_SSO_SECRET\n    redirect_url: <the redirect URL above>\n    allowed_domains: [example.com]\n    role_claim: groups\n    admin_values: [enterplace-admins]\n    self_issue:\n      allowed_domains: [example.com]\n      team: developers\n      expires_days: 30\n```".into(),
            "4. To put people in their own teams by group, list them under `teams:` with `sso_values`, for example `teams: [{ name: payments, sso_values: [payments-eng] }]`.".into(),
            format!("5. Run `enterplace check {policy}` and fix every problem it names. {save}"),
            format!("6. Write me the message for developers: install the enterplace CLI, run `enterplace login {base}`, sign in in the browser, and paste the lines it prints into their shell profile."),
        ],
        &format!(
            "{base}/console/sign-in shows Sign in with single sign-on, and `enterplace login {base}` on a developer's machine prints a key; the developer then shows under People at {base}/console/app/#/people, named by their email."
        ),
        "/governance/single-sign-on/",
    )
}

/// "Copy for your agent" on Stop traffic and Restore traffic: `enterplace kill` and `unkill` with every flag, so an
/// agent stops or restores traffic alone. `stopped`: the switch to turn off, else the prompt stops traffic.
pub(crate) fn kill_prompt(base: &str, stopped: Option<&enterplace_core::kill::Kill>) -> String {
    let setup = format!(
        "1. In the shell you run commands in: `export ENTERPLACE_URL={base}`. Ask me to set ENTERPLACE_ADMIN_KEY to an admin key myself (`export ENTERPLACE_ADMIN_KEY=...`); never ask me to paste it to you, and never print it."
    );
    match stopped {
        Some(kill) => task_prompt(
            base,
            &format!("Restore traffic for {}", kill.label()),
            &[("Switch", kill.label()), ("Stopped because", kill.reason.clone())],
            &[
                setup,
                format!("2. Run `{}`.", crate::pages::unkill_command(kill)),
            ],
            &format!(
                "The command says the switch is off, and the banner on {base}/console/app/#/audit no longer lists it. Requests are let through again within 2 seconds on every gateway."
            ),
            "/governance/kill-switches/",
        ),
        None => task_prompt(
            base,
            "Stop traffic through Enterplace with a kill switch",
            &[],
            &[
                "1. Ask me, if I have not said them: what to stop (a person, a team, one key by its hash prefix, a model, or everything) and the reason. The people stopped see the reason in their tool.".into(),
                setup.replacen("1.", "2.", 1),
                "3. Run exactly one of these, with my answers:\n`enterplace kill --person <name> --reason \"<reason>\"`\n`enterplace kill --team <team> --reason \"<reason>\"`\n`enterplace kill --key-prefix <first 8 hex of the key hash> --reason \"<reason>\"`\n`enterplace kill --model <model> --reason \"<reason>\"`\n`enterplace kill --all --reason \"<reason>\"`\nIf it answers that the name matches nothing, show me the names it suggests; add --force only if I say so.".into(),
                "4. To undo it later: the same command as `enterplace unkill` with the same flag and no --reason.".into(),
            ],
            &format!(
                "The command says the switch is on; the banner on {base}/console/app/#/audit lists it with the reason. Every gateway refuses that traffic within 2 seconds."
            ),
            "/governance/kill-switches/",
        ),
    }
}

/// The `enterplace key new` line of an agent prompt: with the keys file named, so it works from any folder on the
/// gateway's machine, and with the names it still needs asked for, not made up.
fn key_new(f: &Facts, who: &str, flags: &str) -> String {
    format!(
        "Ask me for the {who} and the team if I have not said them. Then, on the machine that runs the gateway, run: `enterplace key new <{who}> --team <team>{flags} --keys {}`. It prints the key once.",
        f.keys_path
    )
}

/// A docs page's Markdown twin, which the docs site serves beside every page.
pub(crate) fn md(path: &str) -> String {
    format!("{DOCS}{}.md", path.trim_end_matches('/'))
}

impl Step {
    fn new(title: &str, done: bool, now: Vec<Value>) -> Step {
        Step {
            title: title.into(),
            optional: false,
            done,
            listens: false,
            now: now.into_iter().filter(|b| !b.is_null()).collect(),
            listen: String::new(),
            done_text: String::new(),
            open: None,
            agent: String::new(),
        }
    }
    fn agent(mut self, text: String) -> Step {
        self.agent = text;
        self
    }
    fn listening(mut self, text: String, open: (&'static str, &'static str)) -> Step {
        self.listens = true;
        self.listen = text;
        self.open = Some(open);
        self
    }
    fn finished(mut self, text: String) -> Step {
        self.done_text = text;
        self
    }
}

/// A key just made on Start here, shown once.
pub(crate) struct Made {
    name: String,
    team: String,
    key: String,
    /// Made by Send your first request, for that request only.
    start: bool,
}

/// Whether `k` is a person token: it names a person on a subscription request and reaches no model on its own.
fn is_person_token(k: &KeyEntry) -> bool {
    k.options.metadata.get("kind").map(String::as_str) == Some(crate::PERSON_TOKEN_KIND)
}

/// Whether `k` is the key Send your first request makes.
fn first_request_key(k: &KeyEntry) -> bool {
    k.options.metadata.get("kind").map(String::as_str) == Some(FIRST_KIND)
}

const FIRST_KIND: &str = "first-request";

struct Ctx<'a> {
    f: &'a Facts,
    admin: &'a Admin,
    track: Track,
    tool: String,
    made: Option<&'a Made>,
    watch_token: Option<&'a str>,
    policy: String,
    /// The Coding agents choice is paid with provider API keys, not Claude subscriptions.
    pay_api: bool,
    /// How step 2 of Claude subscriptions sets Claude Code up: `shell` or `mdm`.
    setup: String,
    /// The signed-in person's own person token, when they pressed Make my person token this run.
    mine: Option<String>,
}

impl Ctx<'_> {
    fn may_keys(&self) -> bool {
        self.admin.may(Permission::IssueKeys)
    }

    /// The form that makes a key, or what to do without the right to.
    fn key_form(&self, label: &str, placeholders: (&str, &str), workload: bool) -> Value {
        if !self.may_keys() {
            return note("Your role cannot make keys. Ask an admin to make this one.");
        }
        let (n, t) = placeholders;
        let mut hidden = json!({ "kind": if workload { "workload" } else { "person" } });
        if self.track == Track::Coding {
            hidden["pay"] = json!(if self.pay_api { "api" } else { "subscriptions" });
        }
        form(
            "key",
            "Make key",
            hidden,
            vec![input("name", label, n), input("team", "Team", t)],
        )
    }

    /// The key to paste: the one just made, else a placeholder that names whose it is.
    fn key(&self, owner: Option<&KeyEntry>) -> String {
        match (self.made.filter(|m| !m.start), owner) {
            (Some(m), _) => m.key.clone(),
            (None, Some(k)) => format!("<key of {}>", k.name),
            (None, None) => "<an Enterplace key>".into(),
        }
    }

    /// Policy lines with the way to add them: a draft in the store's editor, else Copy and the file's path.
    fn lines(&self, id: &str, name: &str, button: &str) -> Value {
        let Some(change) = change(name) else {
            return Value::Null;
        };
        let (_, marks) = apply(&self.policy, &change);
        let way = if self.f.draft && edit::edits_policy(self.admin) {
            json!({ "kind": "draft", "label": button, "href": format!("/console/policy/edit?add={}", enc(name)) })
        } else if self.f.draft {
            json!({ "kind": "cannot", "text": "Your role cannot change the policy. Ask an admin to add these lines." })
        } else {
            json!({
                "kind": "copy",
                "path": self.f.policy_path,
                "text": format!("Add them to {} and save: Enterplace reads it within 2 seconds.", mono(&self.f.policy_path)),
            })
        };
        json!({
            "type": "policy",
            "id": id,
            "marks": marks.iter().map(|(n, l, k)| json!({ "n": n, "text": l, "kind": k })).collect::<Vec<_>>(),
            "plain": marks.iter().map(|(_, l, _)| l.as_str()).collect::<Vec<_>>().join("\n"),
            "way": way,
        })
    }

    fn requests_done(&self) -> String {
        match self.f.sent_by_people().last() {
            Some(r) => format!(
                "First request at {} from {}: {}{}, {}.",
                clock(&r.time),
                mono(r.label("person")),
                agent(r),
                mono(r.label("model")),
                cost(r)
            ),
            None => "First request seen.".into(),
        }
    }
}

fn agent(r: &Row) -> String {
    // Already the tool's name (`insights` reads it with `agent_of`): an app's `App (OpenAI/Python)` stays whole.
    let name = r.label("agent");
    if name.is_empty() {
        String::new()
    } else {
        format!("{name}, ")
    }
}

fn cost(r: &Row) -> String {
    r.cost_usd.map_or_else(
        || "cost not known".into(),
        |c| if r.estimate { money_est(c) } else { money(c) },
    )
}

fn coding_lines(c: &Ctx<'_>, owner: Option<&KeyEntry>, tool: &str) -> Vec<String> {
    tool_lines(c.f.base.as_str(), &c.key(owner), &first_model(c.f), tool)
}

/// The settings of one tool. `model` is one this install serves (`first_model`), so the lines work as copied: a
/// tool left to its own default asks for a model the policy may not have.
fn tool_lines(base: &str, key: &str, model: &str, tool: &str) -> Vec<String> {
    match tool {
        "codex" => vec![
            "# ~/.codex/config.toml".into(),
            format!("model = \"{model}\""),
            "model_provider = \"enterplace\"".into(),
            "[model_providers.enterplace]".into(),
            "name = \"Enterplace\"".into(),
            format!("base_url = \"{base}/v1\""),
            "env_key = \"ENTERPLACE_KEY\"".into(),
            "wire_api = \"responses\"".into(),
            "# then, in the terminal".into(),
            format!("export ENTERPLACE_KEY={key}"),
            "codex".into(),
        ],
        "cursor" => vec![
            "# Cursor Settings, Models, OpenAI API key".into(),
            format!("Override OpenAI Base URL: {base}/v1"),
            format!("OpenAI API key: {key}"),
            "# Cursor's servers send the requests: Enterplace needs a public HTTPS address".into(),
        ],
        // Gemini CLI speaks Google's own API, which only a gemini or vertex provider answers.
        "gemini" => vec![
            format!("export GOOGLE_GEMINI_BASE_URL={base}"),
            format!("export GEMINI_API_KEY={key}"),
            "# its models must be on a gemini or vertex provider: the demo model does not answer it".into(),
            "gemini".into(),
        ],
        "other" | "app" => vec![
            format!("export OPENAI_BASE_URL={base}/v1"),
            format!("export OPENAI_API_KEY={key}"),
        ],
        "anthropic" => vec![
            format!("export ANTHROPIC_BASE_URL={base}"),
            format!("export ANTHROPIC_API_KEY={key}"),
        ],
        "curl" => vec![
            format!("curl {base}/v1/chat/completions \\"),
            format!("  -H \"Authorization: Bearer {key}\" \\"),
            "  -H \"Content-Type: application/json\" \\".into(),
            format!(
                "  -d '{{\"model\":\"{model}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}]}}'"
            ),
        ],
        "openai" => vec![
            format!("export OPENAI_BASE_URL={base}/v1"),
            format!("export OPENAI_API_KEY={key}"),
        ],
        _ => vec![
            format!("export ANTHROPIC_BASE_URL={base}"),
            format!("export ANTHROPIC_API_KEY={key}"),
            "claude".into(),
        ],
    }
}

fn steps(c: &Ctx<'_>) -> Vec<Step> {
    let f = c.f;
    if c.track == Track::Coding && !c.pay_api {
        return subscriptions(c, f);
    }
    let mut list = first_steps(c, f);
    // Watch routes nothing, so there is no model to connect.
    if c.track == Track::Watch {
        list = list.into_iter().skip(1).collect();
    }
    list.extend(match c.track {
        Track::Coding => coding(c, f),
        Track::Apps => apps(c, f),
        Track::Mcp => mcp(c, f),
        Track::Limit => limit(c, f),
        Track::Watch => watch(c, f),
    });
    list
}

/// The model a first request names: the first connected provider's, else the demo model.
fn first_model(f: &Facts) -> String {
    match f.connected.first() {
        Some((_, model)) if !f.demo && !model.is_empty() => model.clone(),
        _ => enterplace_core::usage::DEMO_MODEL.to_string(),
    }
}

/// The lines of the first request, with `key` (the key made for it, or `$ENTERPLACE_KEY`, the admin key the terminal
/// shows).
fn first_lines(base: &str, key: &str, model: &str, lang: &str) -> Vec<String> {
    let env = key.starts_with('$');
    match lang {
        "python" => vec![
            "# pip install openai".into(),
            if env { "import os".into() } else { String::new() },
            "from openai import OpenAI".into(),
            format!(
                "client = OpenAI(base_url=\"{base}/v1\", api_key={})",
                if env { "os.environ[\"ENTERPLACE_KEY\"]".to_string() } else { format!("\"{key}\"") }
            ),
            format!("answer = client.chat.completions.create(model=\"{model}\", messages=[{{\"role\": \"user\", \"content\": \"Say hello\"}}])"),
            "print(answer.choices[0].message.content)".into(),
        ]
        .into_iter()
        .filter(|l| !l.is_empty())
        .collect(),
        "node" => vec![
            "// npm install openai".into(),
            "import OpenAI from \"openai\";".into(),
            format!(
                "const client = new OpenAI({{ baseURL: \"{base}/v1\", apiKey: {} }});",
                if env { "process.env.ENTERPLACE_KEY".to_string() } else { format!("\"{key}\"") }
            ),
            format!("const answer = await client.chat.completions.create({{ model: \"{model}\", messages: [{{ role: \"user\", content: \"Say hello\" }}] }});"),
            "console.log(answer.choices[0].message.content);".into(),
        ],
        _ => vec![
            format!("curl {base}/v1/chat/completions \\"),
            format!("  -H \"Authorization: Bearer {key}\" \\"),
            "  -H \"Content-Type: application/json\" \\".into(),
            format!("  -d '{{\"model\":\"{model}\",\"messages\":[{{\"role\":\"user\",\"content\":\"Say hello\"}}]}}'"),
        ],
    }
}

/// The provider, the key and Connect on one row; the one hint sits under the whole row.
fn connect_form() -> Value {
    let providers: Vec<Value> = enterplace_core::catalog::START_PROVIDERS
        .iter()
        .map(|(id, _)| json!({ "id": id, "label": provider_label(id) }))
        .collect();
    let mut out = form(
        "connect",
        "Connect",
        json!({}),
        vec![
            json!({ "name": "provider", "label": "Provider", "options": providers }),
            json!({ "name": "key", "label": "Provider key", "placeholder": "sk-...", "secret": true }),
        ],
    );
    // The hint goes under the whole row: inside the field it lifts the input above the select.
    out["after"] = json!("Stored encrypted.");
    out
}

/// Connect a model, then Send your first request: the first data on every track, within a minute.
fn first_steps(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let may_connect = c.admin.may(Permission::Credentials) && !c.admin.confined();
    let connect = if !may_connect {
        note("Your role cannot add provider keys. Ask an admin, or try the demo model.")
    } else if !f.credentials_on {
        note(
            "Provider keys are kept sealed under a master key, and this gateway has none. Set ENTERPLACE_MASTER_KEY (64 hex characters) or start Enterplace with enterplace start, which makes one. Meanwhile, try the demo model.",
        )
    } else {
        connect_form()
    };
    let demo = if may_choose(c.admin) && f.demo_in_policy {
        vec![button("Try without a key", "demo", json!({}), true)]
    } else {
        Vec::new()
    };
    // A provider in the policy counts once its connection test passed: added alone, its key or address may be wrong.
    let tests: Vec<(String, Option<crate::tested::Tested>)> = f
        .connected
        .iter()
        .map(|(n, _)| (n.clone(), crate::tested::last(n)))
        .collect();
    let connected: Vec<String> = tests
        .iter()
        .filter(|(_, t)| t.as_ref().is_some_and(|t| t.ok))
        .map(|(n, _)| mono(n))
        .collect();
    let mut body = vec![p(
        "Paste a key from OpenAI, Anthropic or Gemini, and Enterplace sends your requests to that provider. Or try the free demo model: Enterplace answers it with a sample text, so your first request lands in seconds.",
    )];
    for (name, test) in tests
        .iter()
        .filter(|(_, t)| !t.as_ref().is_some_and(|t| t.ok))
    {
        body.push(note(match test {
            Some(t) => format!("{name}: {} Fix it on Providers, where Test connection tries again.", t.text),
            None => format!("{name} is added. Testing its connection now: this step turns done when the test passes."),
        }));
    }
    body.push(connect);
    body.push(actions(demo));
    let s1 = Step::new(
        "Connect a model",
        // A request that arrived proves a model answered it, so this never reads Now above a done first request.
        !connected.is_empty() || f.demo || !f.tries.is_empty(),
        body,
    )
    .finished(if !connected.is_empty() {
        format!("Connected: {}. Its connection test passed; requests to its models go to it.", connected.join(", "))
    } else if !tests.is_empty() {
        let names: Vec<String> = tests.iter().map(|(n, _)| mono(n)).collect();
        format!("Added: {}. Its connection test has not passed yet: see its status on [Providers](/console/app/#/providers).", names.join(", "))
    } else {
        "Using the demo model: answers are sample text, free. Connect a provider any time in [Provider credentials](/console/credentials), or on this step after [changing what to start with](/console/app/#/overview?pick=1).".to_string()
    });
    let lang = match c.tool.as_str() {
        "python" | "node" => c.tool.as_str(),
        _ => "curl",
    };
    let made = c.made.filter(|m| m.start);
    let key = made.map_or("$ENTERPLACE_KEY", |m| m.key.as_str());
    let model = first_model(f);
    let key_note = if made.is_some() {
        "The key made for it is in the lines below, shown once."
    } else if c.may_keys() {
        "The lines use $ENTERPLACE_KEY, the admin key enterplace start printed in the terminal. Or make a key for this request, and it is put in the lines:"
    } else {
        "The lines use $ENTERPLACE_KEY: set it to your Enterplace key."
    };
    let key_button = if made.is_none() && c.may_keys() {
        vec![button(
            "Make a key for this request",
            "first-key",
            json!({}),
            true,
        )]
    } else {
        Vec::new()
    };
    let first = f.tries.last();
    let s2 = Step::new(
        "Send your first request",
        first.is_some(),
        vec![
            p(format!("Run this in a terminal. {key_note}")),
            actions(key_button),
            lines_block(
                "lines-first",
                tabs("tool", "Language", &[("curl", "curl"), ("python", "Python"), ("node", "Node")], lang, json!({})),
                "",
                &first_lines(&f.base, key, &model, lang),
            ),
            note("If the provider refuses it (a wrong key, a model it does not serve), the request still shows in Requests with the provider's answer, and this step turns done."),
        ],
    )
    .listening(
        "Waiting for the first request.".into(),
        ("Open Requests", "/console/requests"),
    )
    .finished(first.map_or_else(String::new, |r| {
        format!(
            "First request at {} from {}: {}, {}{}.",
            clock(&r.time),
            mono(r.label("person")),
            mono(r.label("model")),
            if r.verdict == "refused" { format!("refused ({})", r.code) } else { "allowed".into() },
            r.status.filter(|s| *s >= 400).map_or_else(String::new, |s| format!(", the provider answered {s}"))
        )
    }));
    let base = f.base.as_str();
    let s1 = s1.agent(prompt(
        base,
        "Connect a model provider to Enterplace",
        &[("Policy file", f.policy_path.clone())],
        &[
            "1. Where the gateway runs, set the provider key in its environment before `enterplace start`: OPENAI_PROVIDER_KEY, ANTHROPIC_PROVIDER_KEY or GEMINI_PROVIDER_KEY. I will paste the key value myself; never ask me for it in chat.".into(),
            "2. Restart the gateway with `enterplace start` in the same folder: it adds the provider to the policy.".into(),
            "3. Or, for Claude Code on Claude subscriptions, no key is needed: see the Claude Code guide.".into(),
        ],
        "The console's first step shows the provider as connected.",
        "/getting-started/quickstart/",
    ));
    let s2 = s2.agent(prompt(
        base,
        "Send a first request through Enterplace",
        &[("Model", model.clone()), ("Enterplace key", key.to_string())],
        &[
            "Run this in a terminal (if the key is $ENTERPLACE_KEY, I set it to my Enterplace key first):"
                .into(),
            first_lines(&f.base, key, &model, "curl").join("\n"),
        ],
        "The command prints an answer, or a refusal that names its cause.",
        "/getting-started/quickstart/",
    ));
    vec![s1, s2]
}

fn provider_label(id: &str) -> &'static str {
    match id {
        "openai" => "OpenAI",
        "anthropic" => "Anthropic",
        "gemini" => "Google Gemini",
        _ => "Provider",
    }
}

fn made_text(c: &Ctx<'_>, k: Option<&KeyEntry>) -> String {
    match (c.made.filter(|m| !m.start), k) {
        (Some(m), _) => format!(
            "Key made for {}, team {}. It is shown once, above and in the lines below.",
            mono(&m.name),
            mono(&m.team)
        ),
        (None, Some(k)) => format!(
            "Key made for {}, team {}. It was shown once.",
            mono(&k.name),
            mono(&k.team)
        ),
        (None, None) => "Key made.".into(),
    }
}

fn coding(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    // A person token reaches no model, so on API keys it is not the first person's key: the token enterplace start
    // prints would otherwise tick this step on day one.
    let first = f
        .newest(false)
        .filter(|k| !is_person_token(k))
        .or_else(|| f.people.iter().rev().find(|k| !is_person_token(k)));
    let who = first.map_or("your first person".to_string(), |k| k.name.clone());
    let tool = if c.tool.is_empty() { "claude" } else { &c.tool };
    let senders = f.senders();
    let second = senders.get(1).cloned();
    let s1 = Step::new(
        "Make a key for the first person",
        first.is_some(),
        vec![
            p("Each person gets their own key, so every request carries a name and a team."),
            c.key_form("Name", ("sarah.miller", "platform"), false),
        ],
    )
    .finished(made_text(c, first));
    let (tool_name, tool_doc) = match tool {
        "codex" => ("Codex", "/integrations/codex/"),
        "cursor" => ("Cursor", "/integrations/cursor/"),
        "gemini" => ("Gemini CLI", "/integrations/gemini-cli/"),
        "other" => ("coding tools", "/integrations/coding-tools/"),
        _ => ("Claude Code", "/integrations/claude-code/"),
    };
    let s2 = Step::new(
        "Point your coding agent at Enterplace and send one prompt",
        !f.sent_by_people().is_empty(),
        vec![
            p("Paste these lines where your coding agent runs, then ask it anything. The key from step 3 is already in them."),
            lines_block(
                "lines-coding",
                // The tabs keep the API key answer: without it the view falls back to Claude subscriptions.
                tabs(
                    "tool",
                    "Coding tool",
                    &[("claude", "Claude Code"), ("codex", "Codex"), ("cursor", "Cursor"), ("gemini", "Gemini CLI"), ("other", "Other tools")],
                    tool,
                    json!({ "pay": "api" }),
                ),
                "",
                &coding_lines(c, first, tool),
            ),
            actions(vec![docs_link(&format!("Read the {tool_name} guide"), tool_doc)]),
        ],
    )
    .listening(
        format!("Waiting for the first request from {who}."),
        ("Open Requests", "/console/requests"),
    )
    .finished(c.requests_done());
    let s3 = Step::new(
        "Add a second person",
        senders.len() >= 2,
        vec![
            p("Make a key for one more developer and send them the same lines through your secret manager. With two people, Analytics can compare them."),
            c.key_form("Name", ("mike.johnson", "payments"), false),
        ],
    )
    .finished(format!(
        "{} sent a first request.",
        mono(second.as_deref().unwrap_or("A second person"))
    ));
    let mut s4 = Step::new(
        "Let people make their own keys",
        f.people.iter().any(|k| k.name.contains('@')),
        vec![
            p(format!(
                "Connect single sign-on and let people get their own keys, and each developer runs one command to get a key under their company email.{}",
                if f.self_issue { " Single sign-on is set." } else { "" }
            )),
            command_block(&format!("enterplace login {}", f.base)),
            actions(vec![docs_link("Read Single sign-on", "/governance/single-sign-on/")]),
        ],
    )
    .finished("Someone made their own key through single sign-on.".into());
    s4.optional = true;
    let base = f.base.as_str();
    let s1 = s1.agent(prompt(
        base,
        "Make an Enterplace key for the first developer",
        &[],
        &[format!(
            "{} Send it to the developer through the company's secret manager, never in chat.",
            key_new(f, "name", "")
        )],
        "`enterplace key list` shows the new key.",
        "/integrations/coding-tools/",
    ));
    let s2 = s2.agent(prompt(
        base,
        "Point my coding tool at Enterplace with my Enterplace key",
        &[("Enterplace key", c.key(first))],
        &[
            "Set these lines where the tool runs (my shell profile, or the tool's own settings), then send one prompt:".into(),
            coding_lines(c, first, tool).join("\n"),
        ],
        "The prompt answers and shows in Requests under my name.",
        tool_doc,
    ));
    let s3 = s3.agent(prompt(
        base,
        "Make an Enterplace key for one more developer",
        &[],
        &[format!("{} Send the printed lines to the developer through the company's secret manager, never in chat.", key_new(f, "name", ""))],
        "Their first request shows in Requests.",
        "/integrations/coding-tools/",
    ));
    let s4 = s4.agent(prompt(
        base,
        "Get my own Enterplace key through company single sign-on",
        &[],
        &[
            format!("1. Run `enterplace login {base}` and let me finish the sign-in in the browser."),
            "2. Add the line it prints (`. ~/.config/enterplace/env`) to my shell profile, then open a new shell.".into(),
        ],
        "`enterplace login` prints that I am signed in.",
        "/governance/single-sign-on/",
    ));
    vec![s1, s2, s3, s4]
}

/// Where Claude Code reads managed settings, by system, from its settings documentation.
const MANAGED_SETTINGS: &str = "macOS /Library/Application Support/ClaudeCode/managed-settings.json, Linux /etc/claude-code/managed-settings.json, Windows C:\\Program Files\\ClaudeCode\\managed-settings.json";

/// The person token to paste: the one just made, else a placeholder that names whose it is.
fn person_token(c: &Ctx<'_>, owner: Option<&KeyEntry>) -> String {
    match (c.made.filter(|m| !m.start), owner) {
        (Some(m), _) => m.key.clone(),
        (None, Some(k)) => format!("<person token of {}>", k.name),
        (None, None) => "<person token>".into(),
    }
}

/// The lines that point Claude Code at Enterplace on a Claude subscription: the shell's, or managed settings for MDM.
/// Without a token there is no header line: a placeholder there is what a person, or their agent, pastes as is.
fn subscription_lines(base: &str, token: Option<&str>, mdm: bool) -> Vec<String> {
    if mdm {
        let mut lines = vec!["{".to_string(), "  \"env\": {".into()];
        match token {
            Some(token) => {
                lines.push(format!("    \"ANTHROPIC_BASE_URL\": \"{base}\","));
                lines.push(format!(
                    "    \"ANTHROPIC_CUSTOM_HEADERS\": \"x-enterplace-user: {token}\""
                ));
            }
            None => lines.push(format!("    \"ANTHROPIC_BASE_URL\": \"{base}\"")),
        }
        lines.extend(["  }".to_string(), "}".into()]);
        lines
    } else {
        let mut lines = vec![format!("export ANTHROPIC_BASE_URL={base}")];
        if let Some(token) = token {
            lines.push(format!(
                "export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: {token}\""
            ));
        }
        lines.push("claude   # keep using your normal Claude login".into());
        lines
    }
}

/// The prompt that has a coding agent point Claude Code at Enterplace. It holds every value the agent needs and
/// nothing to fill in: with no token, one line when the provider takes unnamed requests, else the one thing to
/// get from the person, said first.
fn subscription_prompt(base: &str, token: Option<&str>, unnamed_ok: bool) -> String {
    let lines = subscription_lines(base, token, false);
    let lines = lines[..lines.len() - 1].join("\n");
    let mut todo = Vec::new();
    match token {
        Some(_) => todo.push("1. Add these two lines to my shell profile (~/.zshrc or ~/.bashrc), replacing any earlier ANTHROPIC_BASE_URL or ANTHROPIC_CUSTOM_HEADERS lines:".to_string()),
        None if unnamed_ok => todo.push("1. Add this one line to my shell profile (~/.zshrc or ~/.bashrc), replacing any earlier ANTHROPIC_BASE_URL line. Do not ask me for a token and do not make one: none is needed, and my requests show as the person unknown until I add a token on the page myself.".to_string()),
        None => {
            todo.push(format!("0. First ask me for my person token. It starts with enterplace_u_: enterplace start printed it for whoever ran it, and anyone else gets one by pressing Make my person token on {base}/console/app/#/coding?pay=subscriptions."));
            todo.push("1. Add this line to my shell profile (~/.zshrc or ~/.bashrc), and a second one, export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: \" followed by that token inside the quotes:".to_string());
        }
    }
    todo.push(lines);
    todo.push("2. If ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN is set in my profile, ~/.claude/settings.json or .env, remove it: Claude Code must keep using my Claude subscription login. Do not run claude /logout.".into());
    todo.push("3. Open a new shell and run `claude -p \"say hello\"`.".into());
    let mut values = vec![("ANTHROPIC_BASE_URL", base.to_string())];
    if let Some(token) = token {
        values.push((
            "ANTHROPIC_CUSTOM_HEADERS",
            format!("x-enterplace-user: {token}"),
        ));
    }
    prompt(
        base,
        "Route my Claude Code through the company's Enterplace gateway while keeping my own Claude subscription login",
        &values,
        &todo,
        "The prompt answers. If Enterplace refuses it, the error names the cause and the fix.",
        "/integrations/claude-code/",
    )
}

/// The form that makes a person token, or what to do without the right to.
fn token_form(c: &Ctx<'_>, placeholders: (&str, &str)) -> Value {
    if !c.may_keys() {
        return note("Your role cannot make person tokens. Ask an admin to make this one.");
    }
    let (n, t) = placeholders;
    form(
        "key",
        "Make person token",
        json!({ "kind": "person_token" }),
        vec![input("name", "Name", n), input("team", "Team", t)],
    )
}

/// Coding agents on Claude subscriptions (Pro, Max, Team, Enterprise): no Anthropic API key anywhere. Enterplace sends
/// each developer's own Claude login on, and a free person token names who sent it.
fn subscriptions(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let base = f.base.as_str();
    let may_policy = edit::edits_policy(c.admin) && !c.admin.confined();
    let turn_on = if f.passthrough {
        Value::Null
    } else if may_policy {
        actions(vec![button(
            "Turn on Claude subscriptions",
            "passthrough",
            json!({}),
            false,
        )])
    } else {
        note("Your role cannot change the policy. Ask an admin to turn this on.")
    };
    let provider: Vec<String> = enterplace_core::catalog::subscription_provider(&|_| None)
        .lines()
        .map(str::to_string)
        .collect();
    let s1 = Step::new(
        "Turn on Claude subscriptions",
        f.passthrough,
        vec![
            p("Enterplace sends each developer's own Claude login (Pro, Max, Team or Enterprise) to Anthropic unchanged, and never keeps it. Nobody makes an Anthropic API key. Enterplace records tokens and cost (est.), and every rule, guardrail and kill switch applies."),
            turn_on,
            actions(vec![docs_link("Read Subscriptions", "/governance/subscriptions/")]),
        ],
    )
    .finished(format!(
        "On: provider {} sends each person's own Claude login. Enterplace holds no Anthropic key for it.",
        mono(enterplace_core::catalog::SUBSCRIPTION_PROVIDER)
    ))
    .agent(prompt(
        base,
        "Turn on Claude subscription passthrough",
        &[("Policy file", f.policy_path.clone())],
        &[
            "1. Unless the policy already has a provider with `auth: passthrough`, add this provider under `providers:` in the policy file (it holds no key):".into(),
            provider.join("\n"),
            "2. Run `enterplace check <policy file>` and fix anything it reports. A running gateway reads the file within 2 seconds.".into(),
        ],
        "`enterplace check` passes and the policy lists the provider.",
        "/governance/subscriptions/",
    ));
    let first = f.newest(false).or_else(|| f.people.last());
    let who = first.map_or("your first person".to_string(), |k| k.name.clone());
    // A token made on this page, whole. Else a placeholder naming whose token goes there, but only where a name is
    // needed or people already hold tokens: a first run shows one line.
    let made = c.made.filter(|m| !m.start).map(|m| m.key.clone());
    // The signed-in person's own token, made by the button below. It goes in the lines and in what Copy for your
    // agent copies, so their requests carry their name from the first one.
    let own = made
        .clone()
        .filter(|_| c.made.is_some_and(|m| m.name == c.admin.name))
        .or_else(|| c.mine.clone());
    let made = made.or_else(|| own.clone());
    let mdm = c.setup == "mdm";
    // A person token the signed-in person already holds (the one enterplace start printed for whoever ran it): never
    // a second one, the lines name the one to paste. Only the token is shown once, so it cannot be filled in here.
    let held = own.is_none()
        && f.people
            .iter()
            .any(|k| k.name == c.admin.name && is_person_token(k));
    // Managed settings are a rollout, one token per person: they keep the header line, with the place to put it.
    let token = made.clone().or_else(|| {
        if held {
            Some(format!(
                "<the person token enterplace start printed for {}>",
                c.admin.name
            ))
        } else {
            (!f.unnamed_ok || mdm).then(|| person_token(c, first))
        }
    });
    let seen = f.subscribed();
    let first_seen = seen.last();
    let who = if own.is_some() || held {
        c.admin.name.clone()
    } else {
        who
    };
    // The lines carry the signed-in person's token. Without one yet (a restart forgets it, single sign-on never made
    // one), one button makes it in their own name: nothing is made until it is pressed.
    let name_on_requests = if own.is_some() {
        vec![note(format!(
            "The lines carry your person token, so your requests show as {}. It reaches no model on its own.",
            mono(&c.admin.name)
        ))]
    } else if held {
        vec![note(format!(
            "You hold a person token already: put it where the lines say, and your requests show as {}. It starts with enterplace_u_. Lost it? Make a new one on People.",
            mono(&c.admin.name)
        ))]
    } else if c.may_keys() {
        let team = if c.admin.team.is_empty() {
            "people"
        } else {
            c.admin.team.as_str()
        };
        vec![
            actions(vec![button(
                "Make my person token",
                "key",
                json!({ "kind": "person_token", "name": c.admin.name, "team": team }),
                false,
            )]),
            note(if f.unnamed_ok {
                "Puts your name on your requests: the lines above get your token. Until then they show as the person unknown."
            } else {
                "Puts your name on your requests: the lines above get your token. Until then they are refused, because every request needs a name."
            }),
        ]
    } else {
        vec![note(
            "Your role cannot make person tokens. Ask an admin for yours.",
        )]
    };
    let mut body = vec![
        p("Paste this where Claude Code runs. Your Claude login stays as it is."),
        lines_block(
            "lines-subscription",
            // API keys are the default way to pay, so these tabs keep the subscription choice.
            tabs(
                "setup",
                "How to set it",
                &[("shell", "Shell"), ("mdm", "Managed settings (MDM)")],
                if mdm { "mdm" } else { "shell" },
                json!({ "pay": "subscriptions" }),
            ),
            "",
            &subscription_lines(base, token.as_deref(), mdm),
        ),
        // One line under the lines shown: the paths only where the managed settings are, not under the shell lines.
        note(if mdm {
            format!("One file per machine, one token per person: {MANAGED_SETTINGS}.")
        } else {
            "Leave ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN unset.".to_string()
        }),
    ];
    body.extend(name_on_requests);
    let s2 = Step::new("Point Claude Code at Enterplace", !seen.is_empty(), body)
        .listening(
            format!("Waiting for the first request from {who}."),
            ("Open Requests", "/console/requests"),
        )
        .finished(first_seen.map_or_else(String::new, |r| {
            format!(
                "First request at {} from {} on a Claude subscription: {}{}, {}.",
                clock(&r.time),
                mono(r.label("person")),
                agent(r),
                mono(r.label("model")),
                cost(r)
            )
        }))
        .agent(subscription_prompt(base, made.as_deref(), f.unnamed_ok));
    let subscribers = f.subscribers();
    let second = subscribers.get(1).cloned();
    let s3 = Step::new(
        "Add a second person",
        subscribers.len() >= 2,
        vec![
            p("Make a person token for one more developer and send them the same lines. With two people, Analytics can compare them."),
            token_form(c, ("mike.johnson", "payments")),
        ],
    )
    .finished(format!(
        "{} sent a first request.",
        mono(second.as_deref().unwrap_or("A second person"))
    ))
    .agent(prompt(
        base,
        "Make an Enterplace person token for one more developer",
        &[],
        &[
            format!("1. {}", key_new(f, "name", " --identity-only")),
            "2. It prints the person token once with the two lines for Claude Code. Send them to the developer through the company's secret manager, not in chat.".into(),
        ],
        "The developer's first prompt shows under their name in Requests.",
        "/integrations/claude-code/",
    ));
    let mut s4 = Step::new(
        "Let people get their own token",
        f.people.iter().any(|k| k.name.contains('@')),
        vec![
            p(format!(
                "Connect single sign-on and let people get their own keys, and each developer runs one command: it signs them in and sets Claude Code's lines for them.{}",
                if f.self_issue { " Single sign-on is set." } else { "" }
            )),
            command_block(&format!("enterplace login {base}")),
            actions(vec![docs_link("Read Single sign-on", "/governance/single-sign-on/")]),
        ],
    )
    .finished("Someone got their own token through single sign-on.".into())
    // enterplace login fails until single sign-on is set: until then the agent sets that up first.
    .agent(if !f.self_issue {
        sign_on_prompt(
            base,
            &f.policy_path,
            enterplace_core::store::policy_store(std::path::Path::new(&f.policy_path)).is_some(),
        )
    } else { prompt(
        base,
        "Sign in to Enterplace with company single sign-on and set Claude Code up for my subscription",
        &[],
        &[
            format!("1. Run `enterplace login {base}` and finish the sign-in in the browser it opens (I will do the sign-in myself)."),
            "2. Add the line it prints (`. ~/.config/enterplace/env`) to my shell profile.".into(),
            "3. Open a new shell and run `claude -p \"say hello\"`.".into(),
        ],
        "The prompt answers and shows under my email in Requests.",
        "/governance/single-sign-on/",
    ) });
    s4.optional = true;
    vec![s1, s2, s3, s4]
}

/// The policy lines of a change, as text to paste.
fn plain(c: &Ctx<'_>, name: &str) -> String {
    change(name)
        .map(|ch| {
            apply(&c.policy, &ch)
                .1
                .into_iter()
                .map(|(_, l, _)| l)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn apps(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let app = f.newest(true);
    let name = app.map_or("the app".to_string(), |k| k.name.clone());
    let team = app.map_or("support".to_string(), |k| k.team.clone());
    let tool = match c.tool.as_str() {
        "anthropic" | "curl" => c.tool.as_str(),
        _ => "openai",
    };
    let first = app.and_then(|k| {
        f.requests
            .iter()
            .rev()
            .find(|r| r.label("person") == k.name)
    });
    let s1 = Step::new(
        "Make a key for the app",
        app.is_some(),
        vec![
            p("A service key names the app or agent, not a person. Give it the team that owns it."),
            c.key_form("App or agent", ("support-bot", "support"), true),
        ],
    )
    .finished(made_text(c, app));
    let s2 = Step::new(
        "Point your app at Enterplace and send one request",
        first.is_some(),
        vec![
            p("Your app keeps its code and its models, whichever provider serves them (OpenAI, Anthropic, Bedrock, Vertex, Azure or your own). Only the address it calls changes: pick the API format your code already uses and set these lines where it runs."),
            lines_block(
                "lines-apps",
                tabs("tool", "Your code uses", &[("openai", "OpenAI-compatible API"), ("anthropic", "Anthropic API"), ("curl", "Plain HTTP (curl)")], tool, json!({})),
                "",
                &coding_lines(c, app, tool),
            ),
            actions(vec![docs_link("Read Connect a project", "/integrations/connect-a-project/")]),
        ],
    )
    .listening(
        format!("Waiting for the first request from {name}."),
        ("Open Requests", "/console/requests"),
    )
    .finished(first.map_or_else(String::new, |r| {
        format!(
            "First request at {} from {}: {}, {} tokens, {}.",
            clock(&r.time),
            mono(&name),
            mono(r.label("model")),
            crate::html::thousands(
                usize::try_from(r.input_tokens.unwrap_or(0) + r.output_tokens.unwrap_or(0)).unwrap_or(0)
            ),
            cost(r)
        )
    }));
    let s3 = Step::new(
        "Set a monthly budget for the app's team",
        f.budget_for(&team),
        vec![
            p(format!(
                "Add these lines to the policy.{} It counts from the next request.",
                if f.observe {
                    " Observe mode is on, so it records what it would refuse and refuses nothing."
                } else {
                    ""
                }
            )),
            c.lines(
                "lines-budget-team",
                &format!("budget-team:{team}"),
                "Add to a policy draft",
            ),
            actions(vec![docs_link(
                "Read Budgets and rate limits",
                "/governance/budgets-and-rate-limits/",
            )]),
        ],
    )
    .finished(format!("The policy has a budget for {}.", mono(&team)));
    let base = f.base.as_str();
    let budget = plain(c, &format!("budget-team:{team}"));
    let s1 = s1.agent(prompt(
        base,
        "Make an Enterplace service key for the app",
        &[],
        &[format!(
            "{} Keep the key in the app's secret store, never in code.",
            key_new(f, "app name", " --service")
        )],
        "`enterplace key list` shows the key.",
        "/integrations/connect-a-project/",
    ));
    let s2 = s2.agent(prompt(
        base,
        "Send this project's model calls through Enterplace",
        &[("Enterplace key", c.key(app))],
        &[
            "1. Where the app reads its settings, set:".into(),
            coding_lines(c, app, tool).join("\n"),
            "2. Change no code where the SDK reads its base URL from the environment. Remove provider keys from code and committed files.".into(),
            "3. Run the app once, or a single test call.".into(),
        ],
        "The call answers and shows in Requests under the app's name.",
        "/integrations/connect-a-project/",
    ));
    let s3 = s3.agent(prompt(
        base,
        &format!("Set a monthly budget for team {team}"),
        &[("Policy file", f.policy_path.clone())],
        &[
            "Add these lines to the policy file, then run `enterplace check <policy file>`:".into(),
            budget,
        ],
        "`enterplace check` passes; the gateway reads the file within 2 seconds.",
        "/governance/budgets-and-rate-limits/",
    ));
    vec![s1, s2, s3]
}

fn mcp(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let s1 = Step::new(
        "Put an MCP server behind Enterplace",
        !f.mcp_servers.is_empty(),
        vec![
            p("Add the server to the policy and allow its tools in a rule. Enterplace reads the saved policy within 2 seconds, with no restart. Its token goes in `GITHUB_MCP_AUTHORIZATION` (`Bearer` and your GitHub token) where Enterplace runs: a gateway reads its environment when it starts, so set the variable before starting it."),
            c.lines("lines-mcp", "mcp-server", "Add to a policy draft"),
            actions(vec![docs_link("Read MCP gateway", "/governance/mcp-gateway/")]),
        ],
    )
    .finished(format!(
        "{} in the policy.",
        f.mcp_servers.iter().map(|s| mono(s)).collect::<Vec<_>>().join(", ")
    ));
    let call = f.tool_calls.last();
    let s2 = Step::new(
        "Connect an MCP client and call one tool",
        call.is_some(),
        vec![
            p("For Claude Code, run this where it runs. It reads your Enterplace key from `ENTERPLACE_KEY`. Any other client that speaks MCP over Streamable HTTP takes the same address and header."),
            command_block(&format!(
                "claude mcp add --transport http enterplace {}/mcp --header \"Authorization: Bearer $ENTERPLACE_KEY\"",
                f.base
            )),
            actions(vec![link("No key yet? Make one", "/console/app/#/coding?track=coding&pay=api")]),
        ],
    )
    .listening(
        "Waiting for the first tool call.".into(),
        ("Open the Audit log", "/console/audit"),
    )
    .finished(call.map_or_else(String::new, |r| {
        let tool = serde_json::from_str::<Value>(&r.line)
            .ok()
            .and_then(|v| Some(format!("{}.{}", v["server"].as_str()?, v["tool"].as_str()?)))
            .unwrap_or_default();
        format!(
            "First tool call at {}: {} ran {}. {}.",
            clock(&r.time),
            mono(r.label("person")),
            mono(&tool),
            if r.verdict == "allow" { "Allowed" } else { "Refused" }
        )
    }));
    let s3 = Step::new(
        "Ask for approval before a risky tool runs",
        f.approvals > 0,
        vec![
            p("Name the tools an admin approves first. The call waits up to 120 seconds for an answer."),
            c.lines("lines-approve", "approve", "Add to a policy draft"),
            actions(vec![docs_link("Read Tool permissions", "/governance/mcp-gateway/")]),
        ],
    )
    .finished("A call waited for approval and was answered.".into());
    let base = f.base.as_str();
    let s1 = s1.agent(prompt(
        base,
        "Put an MCP server behind Enterplace",
        &[("Policy file", f.policy_path.clone())],
        &[
            "1. Add these lines to the policy file:".into(),
            plain(c, "mcp-server"),
            "2. Where the gateway runs, set GITHUB_MCP_AUTHORIZATION to `Bearer <GitHub token>` (I set the token myself), then restart the gateway.".into(),
        ],
        "`enterplace check <policy file>` passes and the console's MCP pages list the server.",
        "/governance/mcp-gateway/",
    ));
    let s2 = s2.agent(prompt(
        base,
        "Connect my MCP client to Enterplace's MCP gateway and call one tool",
        &[],
        &[
            format!("1. With my Enterplace key in ENTERPLACE_KEY, add an MCP server named enterplace at {base}/mcp (Streamable HTTP) with the header `Authorization: Bearer $ENTERPLACE_KEY`. In Claude Code that is: claude mcp add --transport http enterplace {base}/mcp --header \"Authorization: Bearer $ENTERPLACE_KEY\""),
            "2. Ask my agent to use one of the enterplace tools.".into(),
        ],
        "The tool call answers and shows in the console's Audit log.",
        "/governance/mcp-gateway/",
    ));
    let s3 = s3.agent(prompt(
        base,
        "Make a risky MCP tool wait for an admin's approval",
        &[("Policy file", f.policy_path.clone())],
        &["Add these lines to the first rule of the policy file, then run `enterplace check <policy file>`:".into(), plain(c, "approve")],
        "A call to that tool waits in MCP approvals.",
        "/governance/mcp-gateway/",
    ));
    vec![s1, s2, s3]
}

fn limit(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let first = f.newest(false).or_else(|| f.people.last());
    let tool = match c.tool.as_str() {
        "codex" | "gemini" | "app" => c.tool.as_str(),
        _ => "claude",
    };
    let spent: f64 = f.requests.iter().filter_map(|r| r.cost_usd).sum();
    let s1 = Step::new(
        "Make a key",
        !f.people.is_empty(),
        vec![
            p("A budget counts requests that pass through Enterplace, so traffic comes first. Start with one key."),
            c.key_form("Name", ("sarah.miller", "platform"), false),
        ],
    )
    .finished(made_text(c, first));
    let s2 = Step::new(
        "Send requests through Enterplace",
        !f.requests.is_empty(),
        vec![
            p("Paste these lines where your coding agent runs, or point an app at the same address."),
            lines_block(
                "lines-limit",
                tabs("tool", "Client", &[("claude", "Claude Code"), ("codex", "Codex"), ("gemini", "Gemini CLI"), ("app", "An app")], tool, json!({})),
                "",
                &coding_lines(c, first, tool),
            ),
        ],
    )
    .listening(
        "Waiting for the first request.".into(),
        ("Open Spend", "/console/spend"),
    )
    .finished(f.requests.last().map_or_else(String::new, |r| {
        format!(
            "First request at {}. Spent so far: {}.",
            clock(&r.time),
            money(spent)
        )
    }));
    let s3 = Step::new(
        "Set a monthly budget for each team",
        // Done when every team with traffic is capped, as the rollout's Limit stage counts it.
        (!f.budgets.is_empty() || f.rule_budgets) && f.teams_capped().1.is_empty(),
        vec![
            p(format!(
                "Pick the amount from what you expect each team to spend.{}",
                if f.observe { " Observe mode is on, so a request over the budget is recorded as `would_refuse` and still sent." } else { "" }
            )),
            c.lines("lines-budget-all", "budget-all", "Add to a policy draft"),
            actions(vec![docs_link("Read Budgets and rate limits", "/governance/budgets-and-rate-limits/")]),
        ],
    )
    .finished("A budget is in the policy.".into());
    let s4 = Step::new(
        "Enforce the budget",
        !f.observe,
        vec![
            p("When the numbers look right, delete the observe line. From the next request, a team over its budget is refused with `budget_exceeded`."),
            c.lines("lines-enforce", "enforce", "Turn off observe mode"),
            actions(vec![docs_link("Read Step 3: Limit", "/start/step-3-limit/")]),
        ],
    )
    .finished("Observe mode is off: budgets refuse.".into());
    let base = f.base.as_str();
    let s1 = s1.agent(prompt(
        base,
        "Make an Enterplace key",
        &[],
        &[key_new(f, "name", "")],
        "`enterplace key list` shows the key.",
        "/governance/budgets-and-rate-limits/",
    ));
    let s2 = s2.agent(prompt(
        base,
        "Send requests through Enterplace",
        &[("Enterplace key", c.key(first))],
        &[
            "Set these lines where the tool runs, then send one prompt:".into(),
            coding_lines(c, first, tool).join("\n"),
        ],
        "The request shows in Spend.",
        "/governance/budgets-and-rate-limits/",
    ));
    let s3 = s3.agent(prompt(
        base,
        "Set a monthly budget for each team",
        &[("Policy file", f.policy_path.clone())],
        &[
            "Add these lines to the policy file, then run `enterplace check <policy file>`:".into(),
            plain(c, "budget-all"),
        ],
        "Spend shows each team against its budget.",
        "/governance/budgets-and-rate-limits/",
    ));
    let s4 = s4.agent(prompt(
        base,
        "Enforce the budgets",
        &[("Policy file", f.policy_path.clone())],
        &["Delete the line `mode: observe` from the policy file, then run `enterplace check <policy file>`.".into()],
        "A team over its budget is refused with budget_exceeded.",
        "/start/step-3-limit/",
    ));
    vec![s1, s2, s3, s4]
}

fn watch(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let s1 = Step::new(
        "Add a license with watch mode",
        f.watch_on,
        vec![
            p("Watch mode is part of Enterplace Enterprise and keeps its data in Postgres. This gateway has not turned it on yet."),
            lines_block(
                "lines-license",
                Value::Null,
                "",
                &[
                    "export ENTERPLACE_LICENSE=<your license key>".into(),
                    "export DATABASE_URL=postgres://enterplace@db.example.com/enterplace".into(),
                ],
            ),
            note("Add `store: { postgres_url_env: DATABASE_URL }` to the policy and restart Enterplace."),
            actions(vec![docs_link("Read the license setup", "/deploy/overview/")]),
        ],
    )
    .finished("The license includes watch, and the store answers.".into());
    let token = c.watch_token.unwrap_or("enterplace_watch_...");
    let make = if f.watch_on && !c.admin.read_only {
        form(
            "watch-token",
            "Make watch token",
            json!({}),
            vec![input("team", "Team", "engineering")],
        )
    } else if f.watch_on {
        note("Your role cannot make watch tokens. Ask an owner or admin.")
    } else {
        Value::Null
    };
    let s2 = Step::new(
        "Make a watch token",
        f.watch_tokens > 0 || c.watch_token.is_some(),
        vec![
            p("The token goes into Claude Code's managed settings. People are counted under the team you name."),
            make,
        ],
    )
    .finished(if c.watch_token.is_some() {
        "Token made. It is shown once, inside the settings block below: copy it now.".into()
    } else {
        "A watch token exists. It was shown once, inside the settings block.".into()
    });
    let settings = [
        "{ \"env\": {".to_string(),
        "  \"CLAUDE_CODE_ENABLE_TELEMETRY\": \"1\",".into(),
        "  \"OTEL_METRICS_EXPORTER\": \"otlp\",".into(),
        "  \"OTEL_LOGS_EXPORTER\": \"otlp\",".into(),
        "  \"OTEL_EXPORTER_OTLP_PROTOCOL\": \"http/protobuf\",".into(),
        format!("  \"OTEL_EXPORTER_OTLP_ENDPOINT\": \"{}/otlp\",", f.base),
        format!("  \"OTEL_EXPORTER_OTLP_HEADERS\": \"Authorization=Bearer {token}\""),
        "} }".into(),
    ];
    let seen = f.watched.last();
    let s3 = Step::new(
        "Paste the settings into claude.ai",
        seen.is_some(),
        vec![
            p("As an Owner, open claude.ai, Organization settings, Claude Code, Managed settings. Paste the block and save. Claude Code reads it at its next start."),
            lines_block("lines-watch", Value::Null, "Managed settings", &settings),
            actions(vec![docs_link("Read Claude Team and Enterprise", "/integrations/claude-team/")]),
        ],
    )
    .listening(
        "Waiting for Claude Code telemetry. People appear within minutes of their next session.".into(),
        ("Open Watch", "/console/watch"),
    )
    .finished(seen.map_or_else(String::new, |r| {
        format!(
            "First telemetry at {} from {}: {}.",
            clock(&r.time),
            mono(r.label("person")),
            mono(r.label("model"))
        )
    }));
    let base = f.base.as_str();
    let s1 = s1.agent(prompt(
        base,
        "Turn on Enterplace watch mode",
        &[],
        &["Where the gateway runs, set ENTERPLACE_LICENSE (I paste the license myself) and DATABASE_URL, add `store: { postgres_url_env: DATABASE_URL }` to the policy, and restart the gateway.".into()],
        "Watch appears in the console's navigation.",
        "/integrations/claude-team/",
    ));
    let s2 = s2.agent(prompt(
        base,
        "Make a watch token",
        &[],
        &[format!("Open {base}/console/start?track=watch and make the token there: it is shown once, inside the settings block.")],
        "The settings block shows the token.",
        "/integrations/claude-team/",
    ));
    let s3 = s3.agent(prompt(
        base,
        "Send Claude Code telemetry from Claude Team or Enterprise to Enterplace",
        &[],
        &["As an Owner, open claude.ai, Organization settings, Claude Code, Managed settings, paste this block and save:".into(), settings.join("\n")],
        "People appear in the console's Watch within minutes of their next Claude Code session.",
        "/integrations/claude-team/",
    ));
    vec![s1, s2, s3]
}

/// Each step's state: done, now, listening or ahead. The current step is the first required one not done.
pub(crate) fn states(steps: &[Step]) -> Vec<&'static str> {
    let current = steps
        .iter()
        .position(|s| !s.done && !s.optional)
        .or_else(|| steps.iter().position(|s| !s.done));
    steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if s.done {
                "done"
            } else if Some(i) == current {
                if s.listens { "listening" } else { "now" }
            } else {
                "ahead"
            }
        })
        .collect()
}

fn complete(steps: &[Step]) -> bool {
    steps.iter().all(|s| s.done || s.optional)
}

/// The checklist: each step with its state. Done says what happened in one line, Not yet is the title alone, and
/// the current step holds what to do and its prompt for a coding agent.
fn checklist(steps: &[Step], states: &[&str]) -> Value {
    Value::Array(
        steps
            .iter()
            .zip(states)
            .enumerate()
            .map(|(i, (s, state))| {
                let open = matches!(*state, "now" | "listening");
                json!({
                    "n": i + 1,
                    "title": s.title,
                    "optional": s.optional,
                    "state": state,
                    "word": match *state {
                        "done" => "Done",
                        "now" => "Now",
                        "listening" => "Waiting",
                        _ => "Not yet",
                    },
                    // A done step keeps what it showed, so it opens again for a second tool or person.
                    "body": if open || *state == "done" { s.now.clone() } else { Vec::new() },
                    "agent": if open || *state == "done" { s.agent.as_str() } else { "" },
                    "listen": if *state == "listening" { s.listen.as_str() } else { "" },
                    "open": s.open.filter(|_| *state == "listening").map(|(label, href)| json!({ "label": label, "href": href })),
                    "done_text": if *state == "done" { s.done_text.as_str() } else { "" },
                })
            })
            .collect(),
    )
}

/// The live strip on Start here: where requests come from, the gate, where they go, how many in the last 10 minutes,
/// and the newest three. Only the newest one's disc moves in the app, so each new request crosses the gate once:
/// lime when it passed, flame and held at the gate when it was refused.
fn live_strip(f: &Facts) -> Value {
    let since = enterplace_core::audit::rfc3339(
        std::time::SystemTime::now() - std::time::Duration::from_secs(600),
    );
    // Same format, all UTC: the newest-first times compare as text.
    let recent: Vec<&Row> = f
        .tries
        .iter()
        .take_while(|r| r.time.as_str() >= since.as_str())
        .collect();
    let refused = recent.iter().filter(|r| r.verdict == "refused").count();
    let failed = recent
        .iter()
        .filter(|r| r.outcome() == enterplace_core::insights::Outcome::Error)
        .count();
    let distinct = |of: &dyn Fn(&Row) -> String| {
        let mut seen: Vec<String> = Vec::new();
        for r in &f.tries {
            let v = of(r);
            if !v.is_empty() && !seen.contains(&v) {
                seen.push(v);
            }
            if seen.len() == 3 {
                break;
            }
        }
        seen
    };
    let tools = distinct(&|r: &Row| match r.label("agent") {
        "" => "unknown".to_string(),
        tool => tool.to_string(),
    });
    let providers = distinct(&|r: &Row| r.label("provider").to_string());
    let rows: Vec<Value> = f
        .tries
        .iter()
        .take(3)
        .map(|r| {
            json!({
                "id": r.id,
                "time": time_list(&r.time),
                "person": r.label("person"),
                "model": r.label("model"),
                "refused": r.verdict == "refused",
                "code": if r.verdict == "refused" { pages::code_words(&r.code) } else { String::new() },
                // Let through, and the provider failed it: the app words it (lib/failures.ts), never as Allowed.
                "failed": (r.outcome() == enterplace_core::insights::Outcome::Error).then(|| json!({
                    "code": r.code,
                    "status": r.status,
                    "provider": r.label("provider"),
                })),
            })
        })
        .collect();
    json!({
        "count": format!(
            "{} in the last 10 minutes{}{}",
            enterplace_core::count(recent.len(), "request"),
            if refused == 0 { String::new() } else { format!(", {refused} refused") },
            if failed == 0 { String::new() } else { format!(", {failed} failed") }
        ),
        "tools": tools,
        "providers": providers,
        "rows": rows,
    })
}

/// One of the five steps of a rollout, as the strip shows it.
struct Stage {
    name: &'static str,
    done: bool,
    title: &'static str,
    lead: String,
    why: &'static str,
    action: (&'static str, String),
    guide: (&'static str, &'static str),
    when: Vec<(String, String)>,
}

fn stages(f: &Facts, track: Track) -> Vec<Stage> {
    let week = enterplace_core::insights::now_secs().saturating_sub(7 * 86_400);
    let recent =
        |r: &&Row| enterplace_core::insights::unix_secs(&r.time).is_some_and(|t| t >= week);
    let seen = f.requests.iter().filter(recent).count() + f.watched.iter().filter(recent).count();
    let mut people: Vec<&str> = f
        .requests
        .iter()
        .chain(&f.watched)
        .filter(recent)
        .map(|r| r.label("person"))
        .collect();
    people.sort_unstable();
    people.dedup();
    let (teams, open) = f.teams_capped();
    let capped = teams.len() - open.len();
    let watch = track == Track::Watch;
    let needs = "Needs API traffic through Enterplace. Watched seats are not routed.";
    let yes = |b: bool| {
        if b {
            "Yes".to_string()
        } else {
            "Not yet".to_string()
        }
    };
    vec![
        Stage {
            name: "See",
            done: seen > 0,
            title: "Point your tools at Enterplace",
            lead: format!(
                "{} requests through Enterplace in the last 7 days.",
                crate::html::thousands(seen)
            ),
            why: "Every request then shows which tool, model and key sent it, and what it cost.",
            action: ("Open Requests", "/console/requests".into()),
            guide: ("Read the See guide", "/start/step-1-see/"),
            when: vec![(
                "Enterplace served requests in the last 7 days".into(),
                yes(seen > 0),
            )],
        },
        Stage {
            name: "Know",
            done: people.len() >= 2 || f.self_issue,
            title: "Give everyone their own key",
            lead: format!(
                "{} {} sent requests this week, with {} keys that are not admin keys.",
                people.len(),
                if people.len() == 1 {
                    "person"
                } else {
                    "people"
                },
                f.people.len()
            ),
            why: "With a key each, every request carries one name and one team, and spend splits by person.",
            action: ("Open People and workloads", "/console/people".into()),
            guide: ("Read the Know guide", "/start/step-2-know/"),
            when: vec![
                (
                    "Two or more people sent requests in the last 7 days".into(),
                    format!("{}", people.len()),
                ),
                ("Or single sign-on makes keys".into(), yes(f.self_issue)),
            ],
        },
        Stage {
            name: "Limit",
            done: !watch && !teams.is_empty() && capped == teams.len(),
            title: "Cap what each team spends",
            lead: if watch {
                needs.into()
            } else {
                format!(
                    "{capped} of {} teams with traffic have a budget.",
                    teams.len()
                )
            },
            why: "A budget refuses a team's requests once it is spent, so no bill is a surprise.",
            action: ("Add a budget", f.add_budget_href()),
            guide: ("Read the Limit guide", "/start/step-3-limit/"),
            when: vec![(
                "Every team with traffic has a budget".into(),
                format!("{capped} of {}", teams.len()),
            )],
        },
        Stage {
            name: "Protect",
            done: !watch && f.guarded,
            title: "Keep secrets in",
            lead: if watch {
                needs.into()
            } else if f.guarded {
                "A guardrail runs on requests.".into()
            } else {
                "No guardrail runs on requests yet.".into()
            },
            why: "A guardrail finds secrets and personal data in prompts and answers, in shadow mode first, then enforced.",
            action: ("Open the policy", "/console/policy".into()),
            guide: ("Read the Protect guide", "/start/step-4-protect/"),
            when: vec![("A rule runs a guardrail".into(), yes(f.guarded))],
        },
        Stage {
            name: "Prove",
            done: f.verified,
            title: "Show the record holds",
            lead: if f.verified {
                "The audit chain verified.".into()
            } else {
                "The audit chain has not been verified in this session.".into()
            },
            why: "Each record is chained to the one before it. A check shows nothing was removed or changed. Export to a SIEM and retention are Enterprise.",
            action: ("Open the Audit log", "/console/audit".into()),
            guide: ("Read the Prove guide", "/start/step-5-prove/"),
            when: vec![("Verify chain now passes".into(), yes(f.verified))],
        },
    ]
}

/// The five steps of a rollout, and the first one not done, opened.
fn strip(f: &Facts, track: Track) -> Value {
    let list = stages(f, track);
    let current = list.iter().position(|s| !s.done);
    json!({
        "steps": list.iter().enumerate().map(|(i, s)| json!({
            "name": s.name,
            "state": if s.done { "done" } else if Some(i) == current { "current" } else { "ahead" },
            "word": if s.done { "Done" } else if Some(i) == current { "Current" } else { "Ahead" },
        })).collect::<Vec<_>>(),
        "current": current.map(|i| {
            let s = &list[i];
            json!({
                "n": i + 1,
                "title": s.title,
                "lead": s.lead,
                "why": s.why,
                "action": { "label": s.action.0, "href": s.action.1 },
                "guide": { "label": s.guide.0, "href": format!("{DOCS}{}", s.guide.1) },
                "when": s.when.iter().map(|(t, d)| json!({ "text": t, "value": d })).collect::<Vec<_>>(),
            })
        }),
    })
}

// ---------------------------------------------------------------- the page's answer

struct View<'a> {
    kept: &'a Kept,
    track: Option<Track>,
    tool: String,
    made: Option<&'a Made>,
    watch_token: Option<&'a str>,
    picking: bool,
    pay_api: bool,
    setup: String,
    /// The steps were asked for after the choice was set up and folded.
    checklist: bool,
}

/// What the app polls on: the track and each step's state. When it changes, a view held since a change (a key shown
/// once) gives way to the new one.
fn signature(track: Option<Track>, states: &[&str], complete: bool) -> String {
    format!(
        "{}:{}:{}",
        track.map_or("none", Track::id),
        states.join(","),
        complete
    )
}

fn may_choose(admin: &Admin) -> bool {
    admin.may(Permission::IssueKeys) || edit::edits_policy(admin)
}

/// The Coding agents track pays with API keys, which every coding agent takes, unless Claude subscriptions were picked.
fn pays_api(pay: &str) -> bool {
    pay != "subscriptions"
}

fn view_of<'a>(kept: &'a Kept, query: &Form) -> View<'a> {
    let picking = query.get("pick") == "1";
    View {
        kept,
        track: if picking {
            None
        } else {
            Track::of(query.get("track")).or(kept.choice)
        },
        tool: query.get("tool").to_string(),
        made: None,
        watch_token: None,
        picking,
        pay_api: pays_api(query.get("pay")),
        setup: query.get("setup").to_string(),
        checklist: query.get("view") == "checklist",
    }
}

/// The app route's query that shows `v` again.
fn query_of(v: &View<'_>) -> String {
    let mut out: Vec<String> = Vec::new();
    if let Some(track) = v.track {
        out.push(format!("track={}", track.id()));
        if track == Track::Coding {
            out.push(format!(
                "pay={}",
                if v.pay_api { "api" } else { "subscriptions" }
            ));
        }
    }
    for (name, value) in [("tool", &v.tool), ("setup", &v.setup)] {
        if !value.is_empty() {
            out.push(format!("{name}={}", enc(value)));
        }
    }
    out.join("&")
}

fn track_json(t: Track) -> Value {
    json!({
        "id": t.id(),
        "name": t.name(),
        "button": t.button(),
        "line": t.line(),
        "covers": t.covers(),
        "steps": t.steps(),
        "enterprise": t.enterprise(),
    })
}

/// Everything Start here shows, computed from the gateway's records: the welcome, the pick, a track's checklist, or
/// the five steps once the choice is set up.
fn page_state(console: &Console, admin: &Admin, f: &Facts, v: &View<'_>) -> Value {
    let may = may_choose(admin);
    let mut out = json!({
        "base": f.base,
        "problem": f.problem,
        "may_choose": may,
        "tracks": TRACKS.iter().map(|t| track_json(*t)).collect::<Vec<_>>(),
        "choice": v.kept.choice.map(Track::id),
        "query": query_of(v),
    });
    let Some(track) = v.track else {
        // An empty install with nothing chosen and nothing skipped opens on the welcome. The person token enterplace
        // start makes for the signed-in person does not make it any less empty.
        let welcome = !v.kept.skipped
            && !v.picking
            && f.requests.is_empty()
            && f.people.iter().all(|k| k.name == admin.name);
        out["view"] = json!(if welcome { "welcome" } else { "pick" });
        out["lead"] = json!(if welcome {
            "Pick one. You get a short checklist for it, and the console fills in as each step happens. The rest stays one click away."
        } else {
            "Pick what to start with. You get a short checklist for it, and each step turns done when the gateway sees it happen."
        });
        out["signature"] = json!(signature(None, &[], false));
        out["states"] = json!([]);
        out["complete"] = json!(false);
        return out;
    };
    let ctx = Ctx {
        f,
        admin,
        track,
        tool: v.tool.clone(),
        made: v.made,
        watch_token: v.watch_token,
        policy: policy_text(console),
        pay_api: v.pay_api,
        setup: v.setup.clone(),
        mine: console.mine(&admin.name),
    };
    let list = steps(&ctx);
    let st = states(&list);
    let done = st.iter().filter(|s| **s == "done").count();
    let finished = complete(&list);
    // The first rows are records: shown only to someone who may see records.
    let traffic = admin.may(Permission::SeeRecords) && !f.tries.is_empty();
    let viewing_other = v.kept.choice != Some(track);
    let others: Vec<Value> = TRACKS
        .iter()
        .filter(|t| **t != track)
        .map(|t| track_json(*t))
        .collect();
    out["track"] = json!(track.id());
    out["name"] = json!(track.name());
    out["signature"] = json!(signature(Some(track), &st, finished));
    out["states"] = json!(st);
    out["complete"] = json!(finished);
    out["live"] = if traffic { live_strip(f) } else { Value::Null };
    if finished && v.kept.steps && !viewing_other && !v.checklist {
        out["view"] = json!("folded");
        out["lead"] = json!(format!("{} is set up.", track.name()));
        out["folded"] = json!(format!(
            "{done} of {} done. {} people sent requests through Enterplace.",
            list.len(),
            f.senders().len()
        ));
        out["stages"] = strip(f, track);
        out["others"] = json!(others);
        return out;
    }
    out["view"] = json!("checklist");
    out["lead"] = json!(if traffic {
        format!(
            "Your first requests arrived. {}: {done} of {} done.",
            track.name(),
            list.len()
        )
    } else {
        format!("{}: {done} of {} done.", track.name(), list.len())
    });
    out["viewing"] = json!(if viewing_other && v.kept.choice.is_some() {
        format!(
            "Showing {}. This install started with {}.",
            track.name(),
            v.kept.choice.map_or("", Track::name)
        )
    } else {
        String::new()
    });
    // Coding agents first asks how the team pays. API keys serve every coding agent; a Claude subscription is
    // Claude Code's own login, routed with no API key at all.
    out["pay"] = if track == Track::Coding {
        json!(if v.pay_api { "api" } else { "subscriptions" })
    } else {
        Value::Null
    };
    out["steps"] = checklist(&list, &st);
    out["banner"] = json!(finished && !viewing_other);
    out["others"] = json!(if finished { others } else { Vec::new() });
    out["made"] = v.made.map_or(Value::Null, |m| {
        json!({
            "word": if m.key.starts_with(enterplace_core::id::PERSON_PREFIX) { "Person token" } else { "Key" },
            "name": m.name,
            "team": m.team,
            "key": m.key,
        })
    });
    out
}

// ---------------------------------------------------------------- the API

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links land on the same view there.
        .route("/start", get(|uri: Uri| async move { moved(&uri) }))
        .route(
            "/start/state.json",
            get(|uri: Uri| async move {
                redirect(&format!(
                    "/console/api/start{}",
                    uri.query().map(|q| format!("?{q}")).unwrap_or_default()
                ))
            }),
        )
        .route("/api/start", get(show))
        .route("/api/start/pick", post(pick))
        .route("/api/start/key", post(make_key))
        .route("/api/start/watch-token", post(make_watch_token))
        .route("/api/start/connect", post(connect))
        .route("/api/start/demo", post(use_demo))
        .route("/api/start/first-key", post(first_key))
        .route("/api/start/passthrough", post(turn_on_passthrough))
}

/// The app's Start here route for an old address, keeping what its query asked for.
fn moved(uri: &Uri) -> Response {
    let query = Form::of(uri);
    let kept: Vec<String> = ["track", "pay", "tool", "setup", "pick", "view"]
        .iter()
        .filter(|name| !query.get(name).is_empty())
        .map(|name| format!("{name}={}", enc(query.get(name))))
        .collect();
    // A use case with a page of its own opens there; the other starting choices are on Overview.
    let page = match query.get("track") {
        "coding" => "coding",
        "apps" => "apps",
        "mcp" => "mcp",
        _ => "overview",
    };
    let mut to = format!("/console/app/#/{page}");
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

/// A JSON body, a form, or nothing at all: a button posts no fields.
fn body_or_empty(bytes: &Bytes) -> Result<Map<String, Value>, Fail> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Map::new());
    }
    body_of(bytes)
}

fn is_on(body: &Map<String, Value>, name: &str) -> bool {
    matches!(body.get(name), Some(Value::Bool(true)))
        || matches!(body.get(name), Some(Value::String(s)) if s == "1" || s == "true")
}

/// The view a change was made from, as the app sends it with the change.
fn query_in(body: &Map<String, Value>) -> Form {
    Form(
        ["track", "pay", "tool", "setup"]
            .iter()
            .map(|n| ((*n).to_string(), text(body, n).to_string()))
            .collect(),
    )
}

async fn show(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let mut f = facts(&console, &admin, crate::base()).await;
            let kept = read_kept(&console).unwrap_or_else(|err| {
                f.problem = err;
                Kept::default()
            });
            let view = view_of(&kept, &Form::of(&uri));
            Ok(ok(page_state(&console, &admin, &f, &view)))
        }
        .await,
    )
}

/// Keeps the starting choice, a skip, or that the five steps were asked for.
async fn pick(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !may_choose(&admin) {
                read_only(&console, &admin, "start_choice").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "Your role cannot choose what this install starts with. An admin can.".into(),
                ));
            }
            let body = body_or_empty(&bytes)?;
            let mut kept = read_kept(&console).unwrap_or_default();
            let (target, message) = if is_on(&body, "steps") {
                kept.steps = true;
                (
                    json!({ "steps": true }),
                    "The five steps of a rollout are on Overview.".to_string(),
                )
            } else if is_on(&body, "skip") {
                kept.skipped = true;
                (
                    json!({ "skipped": true }),
                    "Skipped. Overview keeps the choice one click away.".to_string(),
                )
            } else {
                let Some(track) = Track::of(text(&body, "choice")) else {
                    return Err(bad(
                        "Pick what to start with: coding, apps, mcp, limit or watch.",
                    ));
                };
                if kept.choice != Some(track) {
                    kept.steps = false;
                }
                kept.choice = Some(track);
                (
                    json!({ "choice": track.id() }),
                    format!("Showing the steps for {}.", track.steps_for()),
                )
            };
            let act = Act {
                action: "start_choice",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target,
            };
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            write_kept(&console, &kept)
                .map_err(|err| Fail(StatusCode::SERVICE_UNAVAILABLE, err))?;
            Ok(ok(json!({ "message": message })))
        }
        .await,
    )
}

/// A change that shows a key once: the message, the view it was made from, and that view with the key in it.
async fn shown_once(
    console: &Console,
    admin: &Admin,
    view: &View<'_>,
    message: String,
) -> Response {
    let mut f = facts(console, admin, crate::base()).await;
    if let Err(err) = read_kept(console) {
        f.problem = err;
    }
    ok(json!({
        "message": message,
        "query": query_of(view),
        "state": page_state(console, admin, &f, view),
    }))
}

/// Makes a key from a step, through the People page's own issue flow, and shows it once on the checklist.
async fn make_key(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    let admin = match signed_in(&console, &headers, true).await {
        Ok(admin) => admin,
        Err(fail) => return fail.into_response(),
    };
    let body = match body_or_empty(&bytes) {
        Ok(body) => body,
        Err(fail) => return fail.into_response(),
    };
    let (name, team) = (
        text(&body, "name").to_string(),
        text(&body, "team").to_string(),
    );
    let workload = text(&body, "kind") == "workload";
    let token = text(&body, "kind") == "person_token";
    let mut attributes = keyfile::Attributes {
        org: admin.org.clone().unwrap_or_default(),
        customer: match admin.customers.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        },
        ..keyfile::Attributes::default()
    };
    if workload {
        attributes
            .options
            .metadata
            .insert("kind".into(), "workload".into());
    }
    if !admin.may(Permission::IssueKeys) {
        read_only(&console, &admin, "issue_key").await;
        return Fail(
            StatusCode::FORBIDDEN,
            "Your role cannot make keys. Ask an admin to make this one.".into(),
        )
        .into_response();
    }
    if !admin.covers(&attributes.org, &team, attributes.customer.as_deref()) {
        read_only(&console, &admin, "issue_key").await;
        return Fail(
            StatusCode::FORBIDDEN,
            format!(
                "Your role keeps you to team{} {}: make the key in one of them.",
                if admin.teams.len() == 1 { "" } else { "s" },
                admin.teams.join(", ")
            ),
        )
        .into_response();
    }
    let key = match crate::issued_as(&console, &admin, &name, &team, attributes, token).await {
        Ok((key, _)) => key,
        Err(err) => return bad(err).into_response(),
    };
    if token && name == admin.name {
        console.keep_mine(&name, key.clone());
    }
    let made = Made {
        name,
        team,
        key,
        start: false,
    };
    let kept = read_kept(&console).unwrap_or_default();
    let mut view = view_of(&kept, &query_in(&body));
    // The key form of provider API keys says so; a person token is for Claude subscriptions.
    view.pay_api = !token && pays_api(text(&body, "pay"));
    if token {
        view.track = Some(Track::Coding);
    }
    view.made = Some(&made);
    let message = format!(
        "{} made for {}, team {}. Shown once: copy it now.",
        if token { "Person token" } else { "Key" },
        made.name,
        made.team
    );
    shown_once(&console, &admin, &view, message).await
}

/// Makes a watch token through the binary's watch flow and fills it into the settings block, shown once.
async fn make_watch_token(
    State(console): State<Console>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let admin = match signed_in(&console, &headers, true).await {
        Ok(admin) => admin,
        Err(fail) => return fail.into_response(),
    };
    let team = match body_or_empty(&bytes) {
        Ok(body) => text(&body, "team").to_string(),
        Err(fail) => return fail.into_response(),
    };
    let result = match &console.0.watch {
        None => Err(
            "Watch mode is not on: it needs a license that includes watch and a store. See step 1."
                .to_string(),
        ),
        Some(watch) => (watch.token)(console.clone(), admin.clone(), team).await,
    };
    let token = match result {
        Ok(token) => token,
        Err(err) => return bad(err).into_response(),
    };
    let mut kept = read_kept(&console).unwrap_or_default();
    // The token belongs to the watch checklist, whatever was chosen.
    kept.choice = kept.choice.or(Some(Track::Watch));
    let mut view = view_of(&kept, &Form(Vec::new()));
    view.track = Some(Track::Watch);
    view.watch_token = Some(&token);
    shown_once(
        &console,
        &admin,
        &view,
        "Watch token made. It is shown once, inside the settings block: copy it now.".into(),
    )
    .await
}

/// Connect a model: seals the pasted provider key as a credential (recorded, as on Credentials), then adds the
/// provider to the policy, reading its key from that credential. Enterplace uses it within 2 seconds.
async fn connect(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_or_empty(&bytes)?;
            let id = text(&body, "provider").to_string();
            connect_provider(&console, &admin, &id, text(&body, "key"))
                .await
                .map_err(bad)?;
            let mut kept = read_kept(&console).unwrap_or_default();
            kept.demo = false;
            let _ = write_kept(&console, &kept);
            Ok(ok(json!({
                "message": format!("Added {id}. Its key is sealed, and Enterplace tests the connection within a few seconds."),
                "query": "pay=api",
            })))
        }
        .await,
    )
}
async fn connect_provider(
    console: &Console,
    admin: &Admin,
    id: &str,
    value: &str,
) -> Result<(), String> {
    let mut act = Act {
        action: "add_credential",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "name": id, "provider": id, "fingerprint": store::fingerprint(value), "via": "start" }),
    };
    if !admin.may(Permission::Credentials) || admin.confined() {
        read_only(console, admin, "add_credential").await;
        return Err(
            "Your role may not add provider keys, which serve the whole install: ask an admin."
                .into(),
        );
    }
    let problem = if !enterplace_core::catalog::START_PROVIDERS
        .iter()
        .any(|(p, _)| *p == id)
    {
        Some("Pick OpenAI, Anthropic or Google Gemini.".to_string())
    } else {
        store::credential_value_problem(value).map(|p| {
            let mut p = p.to_string();
            if let Some(first) = p.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            p
        })
    };
    if let Some(problem) = problem {
        let _ = record(console, &act, Some("invalid_request"), None).await;
        return Err(problem);
    }
    let c = console.config();
    let Some(vault) = store::credentials_for(&c.keys) else {
        return Err("Provider keys need a master key: set ENTERPLACE_MASTER_KEY (or ENTERPLACE_MASTER_KEY_FILE) and restart Enterplace. enterplace start makes one.".into());
    };
    // A key pasted again for the same provider replaces the one before.
    let exists = vault
        .credentials()
        .map(|list| list.iter().any(|cr| cr.name == id))
        .unwrap_or(false);
    if exists {
        act.action = "rotate_credential";
    }
    record(console, &act, None, None)
        .await
        .map_err(|()| NOT_RECORDED.to_string())?;
    let (n, v, by) = (id.to_string(), value.to_string(), admin.name.clone());
    let stored = tokio::task::spawn_blocking(move || {
        if exists {
            vault.rotate_credential(&n, &v, &by).map(|_| ())
        } else {
            vault.add_credential(&n, &n, &v, &by).map(|_| ())
        }
    })
    .await
    .unwrap_or_else(|err| Err(format!("Nothing was changed: {err}. Try again.")));
    if let Err(err) = stored {
        let _ = record(console, &act, Some("store"), Some(&err)).await;
        return Err(err);
    }
    let policy = policy_text(console);
    let named = config::load(&c.policy, Some(&c.keys))
        .map(|l| l.providers.iter().any(|p| p.name == id))
        .unwrap_or(false);
    if named {
        // The provider is in the policy already: a rotated key is read within 2 seconds.
        return Ok(());
    }
    let env = |name: &str| std::env::var(name).ok();
    let Some(lines) =
        enterplace_core::catalog::start_provider(id, &format!("credential: {id}"), &env)
    else {
        return Err("Pick OpenAI, Anthropic or Google Gemini.".into());
    };
    add_provider(console, admin, id, &policy, &lines).await
}

/// Adds a provider's lines to the policy: a new version in the store, or the file rewritten once the text loads.
async fn add_provider(
    console: &Console,
    admin: &Admin,
    id: &str,
    policy: &str,
    lines: &str,
) -> Result<(), String> {
    let c = console.config();
    let items: Vec<String> = lines.lines().map(str::to_string).collect();
    let (text, _) = apply(policy, &Change::List("providers", items));
    let act = Act {
        action: "connect_provider",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "provider": id, "sha256": enterplace_core::id::sha256_hex(text.as_bytes()), "policy": text }),
    };
    if edit::live(console).is_some() {
        return edit::save_version(
            console,
            admin,
            "connect_provider",
            text,
            edit::live(console).map(|v| v.id),
            format!("Connect provider {id}"),
        )
        .await
        .map(|_| ())
        .map_err(|e| e.message());
    }
    record(console, &act, None, None)
        .await
        .map_err(|()| NOT_RECORDED.to_string())?;
    let (path, keys) = (c.policy.clone(), c.keys.clone());
    let written = tokio::task::spawn_blocking(move || write_policy(&path, &keys, &text))
        .await
        .unwrap_or_else(|err| Err(format!("Nothing was changed: {err}. Try again.")));
    if let Err(err) = &written {
        let _ = record(console, &act, Some("invalid_policy"), Some(err)).await;
    }
    written
}

/// Turn on Claude subscriptions: the passthrough provider goes into the policy. It holds no key, so nothing is sealed.
async fn turn_on_passthrough(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let c = console.config();
            let on = config::load(&c.policy, Some(&c.keys))
                .is_ok_and(|l| l.providers.iter().any(|p| p.passthrough));
            if !on {
                if !edit::edits_policy(&admin) || admin.confined() {
                    read_only(&console, &admin, "connect_provider").await;
                    return Err(Fail(
                        StatusCode::FORBIDDEN,
                        "Your role cannot change the policy. Ask an admin to turn on Claude subscriptions.".into(),
                    ));
                }
                let env = |name: &str| std::env::var(name).ok();
                let lines = enterplace_core::catalog::subscription_provider(&env);
                add_provider(
                    &console,
                    &admin,
                    enterplace_core::catalog::SUBSCRIPTION_PROVIDER,
                    &policy_text(&console),
                    &lines,
                )
                .await
                .map_err(bad)?;
            }
            Ok(ok(json!({
                "message": "Claude subscriptions are on: Enterplace sends each person's own Claude login to Anthropic. Enterplace uses it within 2 seconds.",
                "query": "track=coding&pay=subscriptions",
            })))
        }
        .await,
    )
}

/// Try without a key: the first request goes to the demo model.
async fn use_demo(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !may_choose(&admin) {
                read_only(&console, &admin, "start_choice").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "Your role cannot choose what this install starts with. An admin can.".into(),
                ));
            }
            let mut kept = read_kept(&console).unwrap_or_default();
            kept.demo = true;
            let act = Act {
                action: "start_choice",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({ "demo": true }),
            };
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            write_kept(&console, &kept).map_err(|err| Fail(StatusCode::SERVICE_UNAVAILABLE, err))?;
            Ok(ok(json!({
                "message": "The first request goes to the demo model: answers are sample text, free.",
                "query": "pay=api",
            })))
        }
        .await,
    )
}

/// Makes a key for the first request, through the People page's issue flow, and puts it in the lines, shown once.
async fn first_key(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    let admin = match signed_in(&console, &headers, true).await {
        Ok(admin) => admin,
        Err(fail) => return fail.into_response(),
    };
    let body = match body_or_empty(&bytes) {
        Ok(body) => body,
        Err(fail) => return fail.into_response(),
    };
    let team = admin
        .teams
        .first()
        .cloned()
        .unwrap_or_else(|| "start".to_string());
    let mut attributes = keyfile::Attributes {
        org: admin.org.clone().unwrap_or_default(),
        customer: match admin.customers.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        },
        ..keyfile::Attributes::default()
    };
    attributes
        .options
        .metadata
        .insert("kind".into(), FIRST_KIND.into());
    if !admin.may(Permission::IssueKeys) {
        read_only(&console, &admin, "issue_key").await;
        return Fail(
            StatusCode::FORBIDDEN,
            "Your role cannot make keys. Use your own Enterplace key in the lines.".into(),
        )
        .into_response();
    }
    let key = match crate::issued(&console, &admin, FIRST_KIND, &team, attributes).await {
        Ok((key, _)) => key,
        Err(err) => return bad(err).into_response(),
    };
    let made = Made {
        name: FIRST_KIND.into(),
        team,
        key,
        start: true,
    };
    let kept = read_kept(&console).unwrap_or_default();
    let mut view = view_of(&kept, &query_in(&body));
    view.made = Some(&made);
    shown_once(
        &console,
        &admin,
        &view,
        "Key made for this request. It is in the lines, shown once: copy it now.".into(),
    )
    .await
}
/// Writes the policy file, only if the new text loads: checked beside it, then moved into place.
fn write_policy(path: &std::path::Path, keys: &std::path::Path, text: &str) -> Result<(), String> {
    let temp = path.with_file_name(".enterplace.policy.new.yaml");
    std::fs::write(&temp, text).map_err(|err| {
        format!(
            "{} cannot be written ({err}). Give Enterplace write access to the policy's folder.",
            path.display()
        )
    })?;
    if let Err(errors) = config::load(&temp, Some(keys)) {
        let _ = std::fs::remove_file(&temp);
        return Err(format!(
            "The policy would not load with this provider, so nothing was changed: {}",
            errors.join(" ")
        ));
    }
    std::fs::rename(&temp, path).map_err(|err| {
        let _ = std::fs::remove_file(&temp);
        format!(
            "{} cannot be replaced ({err}). Nothing was changed.",
            path.display()
        )
    })
}

// ---------------------------------------------------------------- empty pages

/// What fills a console page, the one action that does it (the Start here step), and its docs page.
/// The two policy lines that add a first budget, as the Spend empty state shows them on either console.
pub(crate) const BUDGET_LINES: [&str; 2] = [
    "limits:",
    r#"  - { team: "*", budget: { usd: 500, per: month } }"#,
];

pub(crate) struct Empty {
    pub title: &'static str,
    pub body: String,
    pub action: (&'static str, &'static str),
    pub docs: &'static str,
    pub extra: String,
}

/// The empty state of a page: what is missing, the step that fills it, and the docs link.
/// `act` is whether the person may take the action: without it, only the docs link is offered.
pub(crate) fn empty_state(e: &Empty, act: bool) -> String {
    let button = if act {
        format!(
            r#"<a class="g-btn t-body" href="{}">{}</a>"#,
            e.action.1, e.action.0
        )
    } else {
        String::new()
    };
    empty(
        &motif(&["", "", "", ""], &["empty", "empty"], (2, 1), false, true),
        e.title,
        &e.body,
        &format!(
            "{}{}",
            e.extra,
            acts(&format!("{button}{}", docs("Read the docs page", e.docs)))
        ),
    )
}

/// The empty state of a page by its name, with the gateway's address in it.
pub(crate) fn empty_for(page: &str, base: &str) -> Option<Empty> {
    let point = (
        "Point a tool at Enterplace",
        "/console/start?track=coding#step-2",
    );
    let key = ("Make a person token", "/console/start?track=coding#step-2");
    Some(match page {
        "Requests" => Empty {
            title: "No requests yet",
            body: "Point a tool at this gateway. Its first request shows here as it arrives.".into(),
            action: point,
            docs: "/integrations/coding-tools/",
            // The Code tab of the Claude desktop app sets ANTHROPIC_BASE_URL itself, so nothing ever arrives from it.
            extra: format!(
                r#"<p class="t-small g-muted" style="margin: 0">Claude Code on a Claude subscription needs this one line and no key. Other tools take a key: Start here shows their lines.</p>{}<p class="t-small g-muted" style="margin: 0">Using the Claude desktop app? Its Code tab ignores your base URL. Run <span class="t-mono-sm">claude</span> in a terminal.</p>"#,
                command("empty-copy", &format!("export ANTHROPIC_BASE_URL={base}"))
            ),
        },
        "Analytics" => Empty {
            title: "Nothing to rank yet",
            body: "Rankings start with the first request through Enterplace.".into(),
            action: point,
            docs: "/operations/request-log/",
            extra: String::new(),
        },
        "Spend" => Empty {
            title: "No spend and no budgets yet",
            body: "Spend counts from the first request. A budget added now counts from then.".into(),
            action: ("Add a budget", "/console/app/#/policy?add=limit"),
            docs: "/governance/budgets-and-rate-limits/",
            extra: code(&[
                (1, crate::html::yaml_line(BUDGET_LINES[0]), "add"),
                (2, crate::html::yaml_line(BUDGET_LINES[1]), "add"),
            ]),
        },
        "People and workloads" => Empty {
            title: "Only your admin key so far",
            body: "Make a key for each person or app, so every request carries a name.".into(),
            action: key,
            docs: "/governance/keys/",
            extra: command("empty-copy", &format!("enterplace key new sarah.miller --team platform --url {base}")),
        },
        "Teams" => Empty {
            title: "No teams yet",
            body: "A team is set when you make a key.".into(),
            action: ("Make a person token with a team", "/console/start?track=coding#step-2"),
            docs: "/governance/teams/",
            extra: String::new(),
        },
        "Policy" => Empty {
            title: "One rule lets everyone in",
            body: "Every key may use every model, and observe mode blocks nothing.".into(),
            action: ("Edit the policy", "/console/app/#/policy?add=limit"),
            docs: "/governance/policy/",
            extra: String::new(),
        },
        "Alerts" => Empty {
            title: "No alert rules yet",
            body: "Add a channel (Slack, Microsoft Teams, PagerDuty, email or a webhook) and send a test alert. Then add a rule, such as 80% of a team's budget.".into(),
            action: ("Add a channel", "/console/alerts#add-channel"),
            docs: "/operations/alerting/",
            extra: String::new(),
        },
        "Devices" => Empty {
            title: "No devices enrolled",
            body: "Make an enrolment token, then run the device agent from your MDM or by hand. Each machine shows here with the coding tools it found.".into(),
            action: ("Make an enrolment token", "/console/devices#add-token"),
            docs: "/operations/devices/",
            extra: command(
                "empty-copy",
                &format!("ENTERPLACE_DEVICE_TOKEN=enterplace_dev_... enterplace device --control-plane {base} --dry-run"),
            ),
        },
        "Watch" => Empty {
            title: "No Claude Code telemetry yet",
            body: "Make a watch token and paste the settings block into claude.ai, Organization settings, Claude Code, Managed settings. People show here within a few minutes of their next session.".into(),
            action: ("Make a watch token", "/console/start?track=watch#step-4"),
            docs: "/integrations/claude-team/",
            extra: String::new(),
        },
        "MCP approvals" => Empty {
            title: "No MCP servers yet",
            body: "Put an MCP server behind Enterplace and choose which tools each team may use.".into(),
            action: ("Add an MCP server", "/console/start?track=mcp#step-3"),
            docs: "/governance/mcp-gateway/",
            extra: String::new(),
        },
        "Audit log" => Empty {
            title: "Only setup records so far",
            body: "Every request through Enterplace adds a record here, allowed or refused, chained to the one before it. Send one request to see the first.".into(),
            action: point,
            docs: "/governance/audit-log/",
            extra: String::new(),
        },
        _ => return None,
    })
}

/// The empty state of a page as the app lays it out, for an extension's own pages: `null` for a page with none.
pub fn empty_json(page: &str, base: &str) -> Value {
    empty_for(page, base).map_or(Value::Null, |e| {
        json!({
            "title": e.title,
            "body": e.body,
            "action": { "label": e.action.0, "href": e.action.1 },
            "docs": format!("{DOCS}{}", e.docs),
        })
    })
}

/// The empty state of a page, for an extension's own pages (Alerts, Devices, Watch, MCP approvals).
pub fn empty_page(page: &str, base: &str, act: bool) -> String {
    empty_for(page, base).map_or_else(String::new, |e| empty_state(&e, act))
}
#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "version: 1\nmode: observe\nproviders:\n  - name: openai\n    preset: openai\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n";

    #[test]
    fn the_connect_row_has_no_hint_inside_it_and_one_line_under_it() {
        // UX #9: a hint inside the key field lifted the input about 25px above the provider select.
        let form = connect_form();
        let fields = form["fields"].as_array().cloned().unwrap_or_default();
        assert_eq!(fields.len(), 2, "{form}");
        assert!(fields.iter().all(|f| f.get("hint").is_none()), "{form}");
        assert_eq!(form["after"], "Stored encrypted.");
    }

    #[test]
    fn the_provider_price_and_import_prompts_carry_the_check_and_never_ask_for_a_secret() {
        let base = "https://ai.example.com";
        for (prompt, yaml) in [
            (
                provider_prompt(base, "/etc/enterplace/enterplace.policy.yaml", false),
                "preset: groq",
            ),
            (
                price_prompt(base, "/etc/enterplace/enterplace.policy.yaml", true),
                "prices:",
            ),
        ] {
            for part in [
                "Enterplace URL: https://ai.example.com",
                "Policy file: /etc/enterplace/enterplace.policy.yaml",
                "enterplace check /etc/enterplace/enterplace.policy.yaml",
                "Verify:",
                "Docs (Markdown",
                yaml,
            ] {
                assert!(prompt.contains(part), "{part}:\n{prompt}");
            }
        }
        let provider = provider_prompt(base, "p.yaml", false);
        assert!(
            provider.contains("set the key variable on every gateway myself")
                && provider.contains("Never ask me to paste the key to you"),
            "{provider}"
        );
        let stored = price_prompt(base, "p.yaml", true);
        assert!(stored.contains("#/policy/edit"), "{stored}");
        let master = master_key_prompt(base);
        assert!(
            master.contains("ENTERPLACE_MASTER_KEY")
                && master.contains("Never ask me to paste it to you")
                && master.contains("/governance/provider-credentials"),
            "{master}"
        );
        let import = import_prompt(base, "/etc/enterplace/enterplace.keys.yaml");
        assert!(
            import.contains(
                "enterplace key import people.csv --keys /etc/enterplace/enterplace.keys.yaml"
            ) && import.contains("Do not print, log or commit that file"),
            "{import}"
        );
    }

    #[test]
    fn the_claude_code_prompt_never_hands_an_agent_a_placeholder() {
        // Found with a real agent: given `x-enterplace-user: <person token>` it stopped and asked three questions.
        let base = "http://127.0.0.1:8080";
        // No token made, and the provider takes unnamed requests: one line, nothing to ask.
        let one = subscription_prompt(base, None, true);
        assert!(
            one.contains("export ANTHROPIC_BASE_URL=http://127.0.0.1:8080"),
            "{one}"
        );
        assert!(
            !one.contains('<') && !one.contains("ANTHROPIC_CUSTOM_HEADERS="),
            "{one}"
        );
        assert!(one.contains("Do not ask me for a token"), "{one}");
        // A token made on the page goes in whole.
        let two = subscription_prompt(base, Some("enterplace_u_abc"), true);
        assert!(
            two.contains("export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: enterplace_u_abc\""),
            "{two}"
        );
        assert!(!two.contains('<'), "{two}");
        // A provider that needs a name, and no token yet: the one thing to get from me is said first.
        let ask = subscription_prompt(base, None, false);
        assert!(
            ask.contains("Make my person token") && !ask.contains("<person token"),
            "{ask}"
        );
        // The lines on the page: one line until a token exists.
        assert_eq!(subscription_lines(base, None, false).len(), 2);
        assert_eq!(
            subscription_lines(base, Some("enterplace_u_abc"), false).len(),
            3
        );
    }

    #[test]
    fn the_lines_for_a_tool_name_a_model_this_install_serves() {
        // Found with real Codex on a keyless start: left to its default model, its first request was refused.
        let codex = tool_lines(
            "http://127.0.0.1:8080",
            "$ENTERPLACE_KEY",
            "enterplace-demo",
            "codex",
        );
        assert!(
            codex.contains(&"model = \"enterplace-demo\"".to_string()),
            "{codex:?}"
        );
        let curl = tool_lines(
            "http://127.0.0.1:8080",
            "$ENTERPLACE_KEY",
            "enterplace-demo",
            "curl",
        )
        .join("\n");
        assert!(
            curl.contains("\"model\":\"enterplace-demo\"") && !curl.contains("gpt-5-mini"),
            "{curl}"
        );
    }

    #[test]
    fn policy_lines_land_where_the_policy_reads_them() {
        let (text, marks) = apply(POLICY, &change("budget-all").unwrap_or(Change::Remove("")));
        assert!(
            text.ends_with("limits:\n  - { team: \"*\", budget: { usd: 500, per: month } }\n"),
            "{text}"
        );
        assert_eq!(marks.len(), 2);
        let (twice, _) = apply(
            &text,
            &change("budget-team:support").unwrap_or(Change::Remove("")),
        );
        assert_eq!(twice.matches("limits:").count(), 1, "{twice}");
        let (off, marks) = apply(POLICY, &Change::Remove("mode: observe"));
        assert!(!off.contains("mode:") && marks[0].2 == "del");
        let (mcp, _) = apply(POLICY, &change("mcp-server").unwrap_or(Change::Remove("")));
        assert!(
            mcp.contains("    models: [\"*\"]\n    tools: [github.*]\nmcp:\n  - name: github"),
            "{mcp}"
        );
        let (approve, _) = apply(&mcp, &change("approve").unwrap_or(Change::Remove("")));
        assert!(
            approve
                .contains("    tools: [github.*]\n    approve_tools: [github.merge_pull_request]"),
            "{approve}"
        );
        assert!(change("budget-team:bad team").is_none() && change("nope").is_none());
    }

    #[test]
    fn the_current_step_is_the_first_required_one_not_done() {
        let step = |done, listens, optional| Step {
            optional,
            listens,
            ..Step::new("t", done, Vec::new())
        };
        let list = [
            step(true, false, false),
            step(false, true, false),
            step(false, false, false),
            step(false, false, true),
        ];
        assert_eq!(states(&list), ["done", "listening", "ahead", "ahead"]);
        let list = [
            step(true, false, false),
            step(true, true, false),
            step(false, false, true),
        ];
        assert_eq!(states(&list), ["done", "done", "now"]);
        assert!(complete(&list));
    }

    fn list_for(track: Track, pay_api: bool, f: &Facts) -> Vec<Step> {
        let admin = Admin::of_role("noa.bar", "platform", false, crate::Via::Key);
        let ctx = Ctx {
            f,
            admin: &admin,
            track,
            tool: String::new(),
            made: None,
            watch_token: None,
            policy: String::new(),
            pay_api,
            setup: String::new(),
            mine: None,
        };
        steps(&ctx)
    }

    /// A demo request arrived: no provider connected, and the demo model was never chosen on the page.
    fn demo_request_arrived() -> Facts {
        let row = Row {
            verdict: "allow".into(),
            ..Row::default()
        };
        Facts {
            tries: vec![row.clone()],
            requests: vec![row],
            ..Facts::default()
        }
    }

    #[test]
    fn connect_a_model_is_done_once_a_demo_request_has_arrived() {
        // Found on a keyless start: "Connect a model" showed as Now above "Send your first request: Done".
        let f = demo_request_arrived();
        for track in [Track::Coding, Track::Apps, Track::Mcp, Track::Limit] {
            let list = list_for(track, true, &f);
            let st = states(&list);
            assert_eq!(list[0].title, "Connect a model", "{track:?}");
            assert_eq!(st[0], "done", "{track:?}: {st:?}");
            assert_eq!(list[1].title, "Send your first request", "{track:?}");
            assert_eq!(st[1], "done", "{track:?}: {st:?}");
        }
        // Before any request, with nothing connected, it is still the current step.
        let list = list_for(Track::Apps, true, &Facts::default());
        assert_eq!(states(&list)[0], "now");
    }

    #[test]
    fn the_watch_track_has_no_connect_a_model_step() {
        // That track routes nothing, so a model to connect has no meaning there.
        for f in [Facts::default(), demo_request_arrived()] {
            let list = list_for(Track::Watch, false, &f);
            assert!(
                list.iter().all(|s| s.title != "Connect a model"),
                "{:?}",
                list.iter().map(|s| &s.title).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn every_track_lists_all_the_steps_it_counts() {
        let f = demo_request_arrived();
        for (track, pay_api) in [
            (Track::Coding, false),
            (Track::Apps, false),
            (Track::Mcp, false),
            (Track::Limit, false),
            (Track::Watch, false),
        ] {
            assert_eq!(
                list_for(track, pay_api, &f).len(),
                track.steps(),
                "{track:?}"
            );
        }
        // Coding agents with provider API keys has the two first steps and the four of its own.
        assert_eq!(list_for(Track::Coding, true, &f).len(), 6);
    }
}
