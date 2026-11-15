//! Start here, the console home: the first-run welcome, the checklist of the starting choice with live done
//! detection, the first requests, and the five steps once the choice is set up. Built from the approved First run
//! design (Pick, Checklist and the five-step strip are its new components) with the console's tokens only.
//!
//! Every step's state is computed from the gateway's real records: keys, the request log, the policy and, through
//! the extension, watch mode. Nothing is ticked by hand. The starting choice is kept in the store when there is one,
//! else in `gantry-start.json` beside the audit log.

use std::fmt::Write as _;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gantry_core::{
    config::{self, KeyEntry},
    insights::{Query, Row},
    keyfile,
    policy::{Mode, Permission, ScopeKind},
    store,
};
use serde_json::{Value, json};

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED, Tls, edit, foreign,
    html::{Field, code, empty, enc, esc, field, head, icon, motif, tag},
    insights, page, pages, read_only, record, redirect, same_origin, secure,
};

/// The docs site every step links into.
pub(crate) const DOCS: &str = "https://gantry-docs.eliran.me";

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        .route("/start", get(start_page))
        .route("/start/state.json", get(state_json))
        .route("/start/pick", post(pick))
        .route("/start/key", post(make_key))
        .route("/start/watch-token", post(make_watch_token))
}

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
                "Claude Code, Codex, Cursor and the other coding tools your developers use."
            }
            Track::Apps => {
                "Services, scripts and agents in your code that call OpenAI, Anthropic or Gemini."
            }
            Track::Mcp => {
                "Put MCP servers behind Gantry and pick which tools wait for an admin's approval."
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

    fn steps(self) -> usize {
        match self {
            Track::Coding | Track::Limit => 4,
            _ => 3,
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
}

const SETTING: &str = "start";

fn kept_file(console: &Console) -> std::path::PathBuf {
    let audit = &console.config().audit;
    audit.parent().map_or_else(
        || "gantry-start.json".into(),
        |d| d.join("gantry-start.json"),
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
                    "{} cannot be read ({err}). Give Gantry read access to it.",
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
    })
}

fn write_kept(console: &Console, kept: &Kept) -> Result<(), String> {
    let text = json!({
        "choice": kept.choice.map(Track::id),
        "skipped": kept.skipped,
        "steps": kept.steps,
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
                "{} cannot be written ({err}). Give Gantry write access to the audit log's folder.",
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
    /// Keys that are not admin keys, within the person's reach, in file order.
    pub people: Vec<KeyEntry>,
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
}

impl Facts {
    fn names(&self) -> Vec<&str> {
        self.people.iter().map(|k| k.name.as_str()).collect()
    }

    /// Requests sent with a key other than an admin's.
    fn from_people(&self) -> Vec<&Row> {
        let names = self.names();
        self.requests
            .iter()
            .filter(|r| names.contains(&r.label("person")))
            .collect()
    }

    fn senders(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .from_people()
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
        draft: edit::live(console).is_some(),
        watch_on: console.0.watch.is_some(),
        verified: console
            .verified(admin.org.as_deref().unwrap_or(""))
            .is_some_and(|(_, r)| r.is_ok()),
        ..Facts::default()
    };
    if let Ok(loaded) = config::load(&c.policy, Some(&c.keys)) {
        f.observe = loaded.policy.mode() == Mode::Observe;
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
    f.people = config::key_entries(&c.keys, &text)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| !k.admin && admin.covers_entry(k))
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
                    && row.verdict != "refused"
                    && row.path.starts_with("/v1")
                    && !row.path.ends_with("/models")
                {
                    f.requests.push(row);
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

// ---------------------------------------------------------------- small builders

fn copy_button(id: &str) -> String {
    format!(
        r#"<button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="{id}">{}Copy</button>"#,
        icon("copy")
    )
}

fn glink(label: &str, href: &str, small: bool) -> String {
    format!(
        r#"<a class="g-link {}" href="{href}">{label}</a>"#,
        if small { "t-small" } else { "t-body" }
    )
}

fn docs(label: &str, path: &str) -> String {
    glink(label, &format!("{DOCS}{path}"), true)
}

fn acts(inner: &str) -> String {
    format!(r#"<div class="g-setup__actions">{inner}</div>"#)
}

/// Lines to paste, in the Terminal component with Copy. A newline between the lines keeps them apart when copied.
fn block(id: &str, tabs: &str, lines: &[String]) -> String {
    let spans: Vec<String> = lines
        .iter()
        .map(|l| format!("<span>{}</span>", esc(l)))
        .collect();
    format!(
        r#"<div class="g-stack" style="gap: var(--space-2)"><div class="g-check__bar">{}{}</div><div class="g-terminal t-mono" id="{id}">{}</div></div>"#,
        if tabs.is_empty() {
            "<span></span>"
        } else {
            tabs
        },
        copy_button(id),
        spans.join("\n")
    )
}

/// One command, in the Command component with Copy.
fn command(id: &str, text: &str) -> String {
    format!(
        r#"<span class="g-command"><span class="g-command__text t-mono" id="{id}">{}</span>{}</span>"#,
        esc(text),
        copy_button(id)
    )
}

/// Tabs that pick which lines a step shows. Links, so they work without a script.
fn tabs(aria: &str, step: usize, options: &[(&str, &str)], selected: &str) -> String {
    let items: String = options
        .iter()
        .map(|(id, label)| {
            let here = if *id == selected {
                r#" aria-current="true""#
            } else {
                ""
            };
            format!(
                r#"<a class="g-tab t-small" href="/console/start?tool={id}#step-{step}"{here}>{label}</a>"#
            )
        })
        .collect();
    format!(r#"<div class="g-tabs" role="group" aria-label="{aria}">{items}</div>"#)
}

fn mono(text: &str) -> String {
    format!(r#"<span class="t-mono">{}</span>"#, esc(text))
}

fn clock(time: &str) -> String {
    time.get(11..16)
        .map_or_else(|| esc(time), |t| format!("{t} UTC"))
}

fn ent() -> String {
    tag("product", "Enterprise", "")
}

// ---------------------------------------------------------------- the steps

pub(crate) struct Step {
    title: String,
    optional: bool,
    done: bool,
    /// Gantry watches the request log for it, so it listens while it is the current step.
    listens: bool,
    now: String,
    when: String,
    then: String,
    listen: String,
    done_text: String,
    open: Option<(&'static str, &'static str)>,
}

impl Step {
    fn new(title: &str, done: bool, now: String, when: &str, then: &str) -> Step {
        Step {
            title: title.into(),
            optional: false,
            done,
            listens: false,
            now,
            when: when.into(),
            then: then.into(),
            listen: String::new(),
            done_text: String::new(),
            open: None,
        }
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
}

struct Ctx<'a> {
    f: &'a Facts,
    admin: &'a Admin,
    track: Track,
    tool: String,
    made: Option<&'a Made>,
    watch_token: Option<&'a str>,
    error: String,
    policy: String,
}

impl Ctx<'_> {
    fn may_keys(&self) -> bool {
        self.admin.may(Permission::IssueKeys)
    }

    /// The form that makes a key, or what to do without the right to.
    fn key_form(&self, label: &str, placeholders: (&str, &str), workload: bool) -> String {
        if !self.may_keys() {
            return r#"<p class="t-small g-check__muted">Your role cannot make keys. Ask an admin to make this one.</p>"#.into();
        }
        let (n, t) = placeholders;
        let error = if self.error.is_empty() {
            String::new()
        } else {
            pages::alert(&esc(&self.error))
        };
        format!(
            r#"{error}<form class="g-check__form" method="post" action="/console/start/key"><input type="hidden" name="kind" value="{}">{}{}<button class="g-btn t-body" type="submit">Make key</button></form>"#,
            if workload { "workload" } else { "person" },
            field(&Field {
                id: &format!("key-name-{n}"),
                name: "name",
                label,
                value: "",
                mono: true,
                extra: &format!(r#" placeholder="{n}" required autocomplete="off""#),
                hint: "",
                error: "",
            }),
            field(&Field {
                id: &format!("key-team-{n}"),
                name: "team",
                label: "Team",
                value: "",
                mono: true,
                extra: &format!(r#" placeholder="{t}" required autocomplete="off""#),
                hint: "",
                error: "",
            }),
        )
    }

    /// The key to paste: the one just made, else a placeholder that names whose it is.
    fn key(&self, owner: Option<&KeyEntry>) -> String {
        match (self.made, owner) {
            (Some(m), _) => m.key.clone(),
            (None, Some(k)) => format!("<key of {}>", k.name),
            (None, None) => "<a Gantry key>".into(),
        }
    }

    /// Policy lines with the way to add them: a draft in the store's editor, else Copy and the file's path.
    fn lines(&self, id: &str, name: &str, button: &str) -> String {
        let Some(change) = change(name) else {
            return String::new();
        };
        let (_, marks) = apply(&self.policy, &change);
        let shown: Vec<(usize, String, &str)> = marks
            .iter()
            .map(|(n, l, k)| (*n, crate::html::yaml_line(l), *k))
            .collect();
        let plain: Vec<String> = marks.iter().map(|(_, l, _)| l.clone()).collect();
        let hidden = format!(r#"<pre id="{id}" hidden>{}</pre>"#, esc(&plain.join("\n")));
        let way = if self.f.draft && edit::edits_policy(self.admin) {
            format!(
                r#"<a class="g-btn t-body" href="/console/policy/edit?add={}">{button}</a>"#,
                enc(name)
            )
        } else if self.f.draft {
            r#"<span class="t-small g-check__muted">Your role cannot change the policy. Ask an admin to add these lines.</span>"#.into()
        } else {
            format!(
                r#"{}<span class="t-small g-check__muted">Add them to {} and save: Gantry reads it within 2 seconds.</span>"#,
                copy_button(id),
                mono(&self.f.policy_path)
            )
        };
        format!("{}{hidden}{}", code(&shown), acts(&way))
    }

    fn requests_done(&self) -> String {
        match self.f.from_people().last() {
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
    let ua = r.label("agent");
    let name = ua.split('/').next().unwrap_or("");
    if name.is_empty() {
        String::new()
    } else {
        format!("{}, ", esc(name))
    }
}

fn cost(r: &Row) -> String {
    r.cost_usd.map_or_else(
        || "cost not known".into(),
        |c| format!("${}", insights::money(c)),
    )
}

fn coding_lines(c: &Ctx<'_>, owner: Option<&KeyEntry>, tool: &str) -> Vec<String> {
    let (base, key) = (c.f.base.as_str(), c.key(owner));
    match tool {
        "codex" => vec![
            "# ~/.codex/config.toml".into(),
            "model_provider = \"gantry\"".into(),
            "[model_providers.gantry]".into(),
            "name = \"Gantry\"".into(),
            format!("base_url = \"{base}/v1\""),
            "env_key = \"GANTRY_KEY\"".into(),
            "wire_api = \"responses\"".into(),
            "# then, in the terminal".into(),
            format!("export GANTRY_KEY={key}"),
            "codex".into(),
        ],
        "cursor" => vec![
            "# Cursor Settings, Models, OpenAI API key".into(),
            format!("Override OpenAI Base URL: {base}/v1"),
            format!("OpenAI API key: {key}"),
            "# Cursor's servers send the requests: Gantry needs a public HTTPS address".into(),
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
            "  -d '{\"model\":\"gpt-5-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}'".into(),
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
    match c.track {
        Track::Coding => coding(c, f),
        Track::Apps => apps(c, f),
        Track::Mcp => mcp(c, f),
        Track::Limit => limit(c, f),
        Track::Watch => watch(c, f),
    }
}

fn made_text(c: &Ctx<'_>, k: Option<&KeyEntry>) -> String {
    match (c.made, k) {
        (Some(m), _) => format!(
            r#"Key made for {}, team {}. It is shown once, here and in the lines below: copy it now.</p>{}<p class="t-small g-check__muted">Gantry keeps only its hash."#,
            mono(&m.name),
            mono(&m.team),
            command("made-key", &m.key)
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
    let first = f.newest(false).or_else(|| f.people.last());
    let who = first.map_or("your first person".to_string(), |k| k.name.clone());
    let tool = if c.tool.is_empty() { "claude" } else { &c.tool };
    let senders = f.senders();
    let second = senders.get(1).cloned();
    let s1 = Step::new(
        "Make a key for the first person",
        !f.people.is_empty(),
        format!(
            r#"<p class="t-body">Each person gets their own key, so every request carries a name and a team.</p>{}"#,
            c.key_form("Name", ("sarah.miller", "platform"), false)
        ),
        "A key other than an admin key exists.",
        "People and workloads lists the person.",
    )
    .finished(made_text(c, first));
    let s2 = Step::new(
        "Point Claude Code at Gantry and send one prompt",
        !f.from_people().is_empty(),
        format!(
            r#"<p class="t-body">Paste these lines in the terminal where Claude Code runs, then ask it anything. The key from step 1 is already in them.</p>{}{}"#,
            block(
                "lines-coding",
                &tabs(
                    "Coding tool",
                    2,
                    &[("claude", "Claude Code"), ("codex", "Codex"), ("cursor", "Cursor"), ("other", "Other tools")],
                    tool
                ),
                &coding_lines(c, first, tool)
            ),
            acts(&docs("Read the Claude Code guide", "/integrations/claude-code/"))
        ),
        &format!("The first request from {who} arrives."),
        "Requests shows each prompt with its model and cost. Analytics ranks them by tool and model.",
    )
    .listening(
        format!("Listening for the first request from {}. This step turns done by itself.", esc(&who)),
        ("Open Requests", "/console/requests"),
    )
    .finished(c.requests_done());
    let s3 = Step::new(
        "Add a second person",
        senders.len() >= 2,
        format!(
            r#"<p class="t-body">Make a key for one more developer and send them the same lines through your secret manager. With two people, Analytics can compare them.</p>{}"#,
            c.key_form("Name", ("mike.johnson", "payments"), false)
        ),
        "A second person sends a request.",
        "Analytics ranks by person and team. Spend splits by person.",
    )
    .finished(format!(
        "{} sent a first request.",
        mono(second.as_deref().unwrap_or("A second person"))
    ));
    let mut s4 = Step::new(
        "Let people make their own keys",
        f.people.iter().any(|k| k.name.contains('@')),
        format!(
            r#"<p class="t-body">Connect single sign-on with <span class="t-mono">self_issue</span>, and each developer runs one command to get a key under their company email.{}</p>{}{}"#,
            if f.self_issue { " Single sign-on is set." } else { "" },
            command("cmd-login", &format!("gantry login {}", f.base)),
            acts(&docs("Read Single sign-on", "/governance/single-sign-on/"))
        ),
        "Someone makes their own key through single sign-on.",
        "People and workloads lists each key under its owner's email.",
    )
    .finished("Someone made their own key through single sign-on.".into());
    s4.optional = true;
    vec![s1, s2, s3, s4]
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
        format!(
            r#"<p class="t-body">A workload key names the app, not a person. Give it the team that owns it.</p>{}"#,
            c.key_form("Workload", ("support-bot", "support"), true)
        ),
        "The key exists.",
        "People and workloads lists the app as a workload.",
    )
    .finished(made_text(c, app));
    let s2 = Step::new(
        "Change the base URL and send one request",
        first.is_some(),
        format!(
            r#"<p class="t-body">Set these variables where the app runs. The SDKs read them, so the code stays as it is.</p>{}{}"#,
            block(
                "lines-apps",
                &tabs("Client", 2, &[("openai", "OpenAI SDKs"), ("anthropic", "Anthropic SDKs"), ("curl", "curl")], tool),
                &coding_lines(c, app, tool)
            ),
            acts(&docs("Read Connect a project", "/integrations/connect-a-project/"))
        ),
        &format!("The first request from {name} arrives."),
        "Requests shows each call with its model, tokens and cost.",
    )
    .listening(
        format!("Listening for the first request from {}. This step turns done by itself.", esc(&name)),
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
        format!(
            r#"<p class="t-body">Add these lines to the policy.{} It counts from the next request.</p>{}{}"#,
            if f.observe { " Observe mode is on, so it records what it would refuse and refuses nothing." } else { "" },
            c.lines("lines-budget-team", &format!("budget-team:{team}"), "Add to a policy draft"),
            acts(&docs("Read Budgets and rate limits", "/governance/budgets-and-rate-limits/"))
        ),
        &format!("The policy has a budget for {team}."),
        &format!("Spend shows {team} against $200, with the day it runs out at today's pace."),
    )
    .finished(format!("The policy has a budget for {}.", mono(&team)));
    vec![s1, s2, s3]
}

fn mcp(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let s1 = Step::new(
        "Put an MCP server behind Gantry",
        !f.mcp_servers.is_empty(),
        format!(
            r#"<p class="t-body">Add the server to the policy and allow its tools in a rule. Set <span class="t-mono">GITHUB_MCP_AUTHORIZATION</span> to <span class="t-mono">Bearer</span> and your GitHub token where Gantry runs, then restart it: a new server needs a restart.</p>{}{}"#,
            c.lines("lines-mcp", "mcp-server", "Add to a policy draft"),
            acts(&docs("Read MCP gateway", "/governance/mcp-gateway/"))
        ),
        "The policy lists an MCP server.",
        "The MCP pages list the server and the tools it offers.",
    )
    .finished(format!(
        "{} in the policy.",
        f.mcp_servers.iter().map(|s| mono(s)).collect::<Vec<_>>().join(", ")
    ));
    let call = f.tool_calls.last();
    let s2 = Step::new(
        "Connect Claude Code and call one tool",
        call.is_some(),
        format!(
            r#"<p class="t-body">Run this where Claude Code runs. It reads your Gantry key from <span class="t-mono">GANTRY_KEY</span>.</p>{}{}"#,
            command(
                "cmd-mcp",
                &format!(
                    "claude mcp add --transport http gantry {}/mcp --header \"Authorization: Bearer $GANTRY_KEY\"",
                    f.base
                )
            ),
            acts(&glink("No key yet? Make one", "/console/start?track=coding#step-1", true))
        ),
        &format!("The first tool call arrives at {}/mcp.", f.base),
        "The audit log shows each tool call with the person, the tool and the decision.",
    )
    .listening(
        "Listening for the first tool call. This step turns done by itself.".into(),
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
        format!(
            r#"<p class="t-body">Name the tools an admin approves first. The call waits up to 120 seconds for an answer.</p>{}{}"#,
            c.lines("lines-approve", "approve", "Add to a policy draft"),
            acts(&docs("Read Tool permissions", "/governance/mcp-gateway/"))
        ),
        "The first call waits for approval and is answered.",
        "MCP approvals shows the waiting call with Approve and Deny.",
    )
    .finished("A call waited for approval and was answered.".into());
    vec![s1, s2, s3]
}

fn limit(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let first = f.newest(false).or_else(|| f.people.last());
    let tool = match c.tool.as_str() {
        "codex" | "app" => c.tool.as_str(),
        _ => "claude",
    };
    let spent: f64 = f.requests.iter().filter_map(|r| r.cost_usd).sum();
    let s1 = Step::new(
        "Make a key",
        !f.people.is_empty(),
        format!(
            r#"<p class="t-body">A budget counts requests that pass through Gantry, so traffic comes first. Start with one key.</p>{}"#,
            c.key_form("Name", ("sarah.miller", "platform"), false)
        ),
        "A key other than an admin key exists.",
        "People and workloads lists the person.",
    )
    .finished(made_text(c, first));
    let s2 = Step::new(
        "Send requests through Gantry",
        !f.requests.is_empty(),
        format!(
            r#"<p class="t-body">Paste these lines where Claude Code runs, or point an app at the same address.</p>{}"#,
            block(
                "lines-limit",
                &tabs("Client", 2, &[("claude", "Claude Code"), ("codex", "Codex"), ("app", "An app")], tool),
                &coding_lines(c, first, tool)
            )
        ),
        "The first request arrives.",
        "Spend counts from the first request.",
    )
    .listening(
        "Listening for the first request. This step turns done by itself.".into(),
        ("Open Spend", "/console/spend"),
    )
    .finished(f.requests.last().map_or_else(String::new, |r| {
        format!(
            "First request at {}. Spent so far: ${}.",
            clock(&r.time),
            insights::money(spent)
        )
    }));
    let s3 = Step::new(
        "Set a monthly budget for each team",
        !f.budgets.is_empty() || f.rule_budgets,
        format!(
            r#"<p class="t-body">Pick the amount from what you expect each team to spend.{}</p>{}{}"#,
            if f.observe { r#" Observe mode is on, so a request over the budget is recorded as <span class="t-mono">would_refuse</span> and still sent."# } else { "" },
            c.lines("lines-budget-all", "budget-all", "Add to a policy draft"),
            acts(&docs("Read Budgets and rate limits", "/governance/budgets-and-rate-limits/"))
        ),
        "A budget is in the policy.",
        "Spend shows each team against its budget. Analytics forecasts the day it runs out.",
    )
    .finished("A budget is in the policy.".into());
    let s4 = Step::new(
        "Enforce the budget",
        !f.observe,
        format!(
            r#"<p class="t-body">When the numbers look right, delete the observe line. From the next request, a team over its budget is refused with <span class="t-mono">budget_exceeded</span>.</p>{}{}"#,
            c.lines("lines-enforce", "enforce", "Turn off observe mode"),
            acts(&docs("Read Step 3: Limit", "/start/step-3-limit/"))
        ),
        "Observe mode is off.",
        "Refused requests show on the Audit log with the code and the date the budget starts again.",
    )
    .finished("Observe mode is off: budgets refuse.".into());
    vec![s1, s2, s3, s4]
}

fn watch(c: &Ctx<'_>, f: &Facts) -> Vec<Step> {
    let s1 = Step::new(
        "Add a license with watch mode",
        f.watch_on,
        format!(
            r#"<p class="t-body">Watch mode is part of Gantry Enterprise and keeps its data in Postgres. This gateway has not turned it on yet.</p>{}<p class="t-small g-check__muted">Add <span class="t-mono">store: {{ postgres_url_env: DATABASE_URL }}</span> to the policy and restart Gantry.</p>{}"#,
            block(
                "lines-license",
                "",
                &[
                    "export GANTRY_LICENSE=<your license key>".into(),
                    "export DATABASE_URL=postgres://gantry@db.example.com/gantry".into(),
                ]
            ),
            acts(&docs("Read License", "/deploy/license/"))
        ),
        "The license includes watch and the store answers.",
        "Watch appears in the nav.",
    )
    .finished("The license includes watch, and the store answers.".into());
    let token = c.watch_token.unwrap_or("gantry_watch_...");
    let may = f.watch_on && !c.admin.read_only;
    let form = if may {
        let error = if c.error.is_empty() {
            String::new()
        } else {
            pages::alert(&esc(&c.error))
        };
        format!(
            r#"{error}<form class="g-check__form" method="post" action="/console/start/watch-token">{}<button class="g-btn t-body" type="submit">Make watch token</button></form>"#,
            field(&Field {
                id: "watch-team",
                name: "team",
                label: "Team",
                value: "",
                mono: true,
                extra: r#" placeholder="engineering" required autocomplete="off""#,
                hint: "",
                error: "",
            })
        )
    } else if f.watch_on {
        r#"<p class="t-small g-check__muted">Your role cannot make watch tokens. Ask an owner or admin.</p>"#.into()
    } else {
        String::new()
    };
    let s2 = Step::new(
        "Make a watch token",
        f.watch_tokens > 0 || c.watch_token.is_some(),
        format!(
            r#"<p class="t-body">The token goes into Claude Code's managed settings. People are counted under the team you name.</p>{form}"#
        ),
        "A watch token exists.",
        "The settings block shows here, ready to paste.",
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
        format!(
            r#"<p class="t-body">As an Owner, open claude.ai, Organization settings, Claude Code, Managed settings. Paste the block and save. Claude Code reads it at its next start.</p>{}{}"#,
            block(
                "lines-watch",
                r#"<span class="t-tag g-caps g-muted">Managed settings</span>"#,
                &settings
            ),
            acts(&docs("Read Claude Team and Enterprise", "/integrations/claude-team/"))
        ),
        "Claude Code telemetry arrives.",
        "Watch lists each person by their Claude email, with sessions, tokens and estimated cost.",
    )
    .listening(
        "Listening for Claude Code telemetry. People appear within a few minutes of their next session.".into(),
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

// ---------------------------------------------------------------- components

/// Pick: the one starting choice. A radio per row, built on Choice and Row.
fn pick_form(selected: Option<Track>, may: bool) -> String {
    let checked = selected.unwrap_or(Track::Coding);
    let opts: String = TRACKS
        .iter()
        .map(|t| {
            format!(
                r#"<label class="g-pick__opt g-choice"><input type="radio" name="choice" value="{}" data-button="{}"{}{}><span class="g-pick__text"><span class="g-pick__head"><span class="t-body-strong">{}</span>{}</span><span class="t-small">{}</span><span class="g-pick__meta t-small">{} steps</span></span></label>"#,
                t.id(),
                t.button(),
                if *t == checked { " checked" } else { "" },
                if may { "" } else { " disabled" },
                t.name(),
                if t.enterprise() { ent() } else { String::new() },
                t.line(),
                t.steps()
            )
        })
        .collect();
    let actions = if may {
        acts(&format!(
            r#"<button class="g-btn t-body" type="submit" data-start-button>Start with {}</button><button class="g-link t-body" type="submit" name="skip" value="1" style="background: none; border: 0; padding: 0; cursor: pointer">Skip and open the console</button>"#,
            checked.button()
        ))
    } else {
        r#"<p class="t-small g-muted">Your role cannot choose what this install starts with. An admin can.</p>"#.into()
    };
    format!(
        r#"<form class="g-stack" style="gap: var(--space-8)" method="post" action="/console/start/pick"><fieldset class="g-pick"><legend class="t-tag g-caps g-muted" style="padding: 0 0 var(--space-2) var(--space-6)">Start with</legend>{opts}</fieldset>{actions}</form>"#
    )
}

/// Checklist: one row per step, its marker carrying the state.
fn checklist(steps: &[Step], states: &[&str], only_open: bool) -> String {
    let mut out = String::from(r#"<ol class="g-check">"#);
    for (i, (s, state)) in steps.iter().zip(states).enumerate() {
        if only_open && *state == "done" {
            continue;
        }
        let mark = match *state {
            "done" => r#"<svg class="g-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>"#.to_string(),
            "listening" => r#"<span class="g-check__pulse"></span>"#.into(),
            _ => String::new(),
        };
        let word = match *state {
            "done" => "Done",
            "now" => "Now",
            "listening" => "Listening",
            _ => "Not yet",
        };
        let terms = format!(
            r#"<dl class="g-check__terms t-small"><div><dt>Turns done when</dt><dd>{}</dd></div><div><dt>Then you see</dt><dd>{}</dd></div></dl>"#,
            esc(&s.when),
            esc(&s.then)
        );
        let body = match *state {
            "done" => format!(
                r#"<p class="t-small g-check__muted">{}</p>{}"#,
                s.done_text,
                s.open
                    .map(|(label, href)| acts(&glink(label, href, true)))
                    .unwrap_or_default()
            ),
            "now" => format!("{}{terms}", s.now),
            "listening" => format!(
                r#"{}<p class="g-check__listen t-body" role="status"><span class="g-loading" aria-hidden="true"><i></i><i></i><i></i></span>{}</p>{}{terms}"#,
                s.now,
                s.listen,
                acts(&glink("Check now", "/console/start", true))
            ),
            _ => format!(r#"<p class="t-small g-check__muted">{}</p>"#, esc(&s.then)),
        };
        let current = if matches!(*state, "now" | "listening") {
            r#" aria-current="step""#
        } else {
            ""
        };
        let _ = write!(
            out,
            r#"<li class="g-check__item" id="step-{}" data-state="{state}"{current}><span class="g-check__mark" aria-hidden="true">{mark}</span><div class="g-check__head"><span class="g-check__title {}">{}{}</span><span class="g-check__state t-small">{word}</span></div><div class="g-check__body">{body}</div></li>"#,
            i + 1,
            if *state == "ahead" { "t-body" } else { "t-sm" },
            esc(&s.title),
            if s.optional {
                tag("", "Optional", "")
            } else {
                String::new()
            }
        );
    }
    out + "</ol>"
}

fn observe_banner(f: &Facts) -> String {
    if !f.observe {
        return String::new();
    }
    r#"<div class="g-banner" role="status"><span class="t-body">Observe mode: nothing is blocked. A request the policy would refuse is recorded as <span class="t-mono">would_refuse</span>.</span></div>"#.into()
}

/// The first requests on Start here, with a reading of each part.
fn first_data(f: &Facts) -> String {
    let rows: Vec<&Row> = f.requests.iter().take(5).collect();
    let since = f
        .requests
        .last()
        .map(|r| clock(&r.time))
        .unwrap_or_default();
    let people = {
        let mut p: Vec<&str> = f.requests.iter().map(|r| r.label("person")).collect();
        p.sort_unstable();
        p.dedup();
        p.len()
    };
    let total: f64 = f.requests.iter().filter_map(|r| r.cost_usd).sum();
    let stat = |figure: String, label: &str| {
        format!(
            r#"<div class="g-stat"><p class="g-stat__figure t-lg">{figure}</p><p class="g-stat__label t-small">{label}</p></div>"#
        )
    };
    let body: String = rows
        .iter()
        .map(|r| {
            let decision = if r.line.contains("would_refuse") {
                tag("refused", "Would refuse", "")
            } else {
                tag("allow", "Allowed", "")
            };
            format!(
                r#"<tr><td class="t-mono-sm g-table__wide">{}</td><td class="t-mono-sm">{}<span class="g-table__sub t-mono-sm">{}</span></td><td class="t-mono-sm g-table__wide">{}</td><td class="t-mono-sm g-table__wide">{}</td><td class="t-mono-sm g-table__num g-table__wide">{}</td><td class="t-mono-sm g-table__num">{}</td><td class="g-table__wide">{decision}</td></tr>"#,
                esc(r.time.get(11..19).unwrap_or(&r.time)),
                esc(r.label("person")),
                esc(r.label("model")),
                esc(r.label("agent").split('/').next().unwrap_or("")),
                esc(r.label("model")),
                crate::html::thousands(
                    usize::try_from(r.input_tokens.unwrap_or(0) + r.output_tokens.unwrap_or(0)).unwrap_or(0)
                ),
                cost(r)
            )
        })
        .collect();
    let points = [
        (
            "One row per request",
            "Each tool sent these through Gantry with a person's key. Nothing else changed for them.",
        ),
        (
            "The model",
            "A coding tool may use a small model for quick tasks. Each row shows the model that answered and its price.",
        ),
        (
            "Cost",
            "From the provider's token counts at the model's price per million tokens, as listed on Models.",
        ),
        (
            "Allowed",
            "Observe mode sends every request from a known key and records what a rule would refuse.",
        ),
        (
            "Also in the Audit log",
            "Each row is a record chained to the one before it, so a removed record shows.",
        ),
    ];
    let dl: String = points
        .iter()
        .map(|(t, d)| {
            format!(r#"<div><dt class="t-body">{t}</dt><dd class="t-small">{d}</dd></div>"#)
        })
        .collect();
    format!(
        r#"<div class="g-setup__cols"><section class="g-panel g-stack" style="align-content: start"><div class="g-stack" style="gap: var(--space-1)"><h2 class="t-sm">First requests through Gantry</h2><p class="t-small g-muted">Since {since}.</p></div><div class="g-stats">{}{}{}</div><div class="g-table-wrap"><table class="g-table g-table--stack"><thead><tr><th class="t-tag">Time (UTC)</th><th class="t-tag">Person</th><th class="t-tag g-table__wide">Tool</th><th class="t-tag g-table__wide">Model</th><th class="t-tag g-table__num g-table__wide">Tokens</th><th class="t-tag g-table__num">Cost</th><th class="t-tag g-table__wide">Decision</th></tr></thead><tbody>{body}</tbody></table></div>{}</section><section class="g-stack" style="align-content: start"><h2 class="t-sm">What you are seeing</h2><dl class="g-points">{dl}</dl></section></div>"#,
        stat(crate::html::thousands(f.requests.len()), "Requests"),
        stat(
            people.to_string(),
            if people == 1 { "Person" } else { "People" }
        ),
        stat(format!("${}", insights::money(total)), "Cost"),
        acts(&format!(
            "{}{}",
            glink("Open Requests", "/console/requests", true),
            glink("Open Analytics", "/console/analytics", true)
        )),
    )
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
    let week = gantry_core::insights::now_secs().saturating_sub(7 * 86_400);
    let recent = |r: &&Row| gantry_core::insights::unix_secs(&r.time).is_some_and(|t| t >= week);
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
    let mut teams: Vec<&str> = f
        .requests
        .iter()
        .filter(recent)
        .map(|r| r.label("team"))
        .filter(|t| !t.is_empty())
        .collect();
    teams.sort_unstable();
    teams.dedup();
    let capped = teams.iter().filter(|t| f.budget_for(t)).count();
    let watch = track == Track::Watch;
    let needs = "Needs API traffic through Gantry. Watched seats are not routed.";
    vec![
        Stage {
            name: "See",
            done: seen > 0,
            title: "Point your tools at Gantry",
            lead: format!(
                "{} requests through Gantry in the last 7 days.",
                crate::html::thousands(seen)
            ),
            why: "Every request then shows which tool, model and key sent it, and what it cost.",
            action: ("Open Requests", "/console/requests".into()),
            guide: ("Read the See guide", "/start/step-1-see/"),
            when: vec![(
                "Gantry served requests in the last 7 days".into(),
                if seen > 0 {
                    "Yes".into()
                } else {
                    "Not yet".into()
                },
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
                (
                    "Or single sign-on makes keys".into(),
                    if f.self_issue {
                        "Yes".into()
                    } else {
                        "Not yet".into()
                    },
                ),
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
            action: ("Add a budget", "/console/start?track=limit#step-3".into()),
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
            when: vec![(
                "A rule runs a guardrail".into(),
                if f.guarded {
                    "Yes".into()
                } else {
                    "Not yet".into()
                },
            )],
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
            when: vec![(
                "Verify chain now passes".into(),
                if f.verified {
                    "Yes".into()
                } else {
                    "Not yet".into()
                },
            )],
        },
    ]
}

fn strip(f: &Facts, track: Track) -> String {
    let list = stages(f, track);
    let current = list.iter().position(|s| !s.done);
    let mut out = String::from(r#"<ol class="g-steps g-setup">"#);
    for (i, s) in list.iter().enumerate() {
        let (attr, word) = if s.done {
            (r#" data-state="done""#, "Done")
        } else if Some(i) == current {
            (r#" aria-current="step""#, "Current")
        } else {
            ("", "Ahead")
        };
        let _ = write!(
            out,
            r#"<li class="g-step"{attr}><span class="t-md">{}</span><span class="g-step__label t-small">{word}</span></li>"#,
            s.name
        );
    }
    if let Some(i) = current {
        let s = &list[i];
        let points: String = s
            .when
            .iter()
            .map(|(t, d)| {
                format!(
                    r#"<div><dt class="t-body">{}</dt><dd class="t-small">{}</dd></div>"#,
                    esc(t),
                    esc(d)
                )
            })
            .collect();
        let _ = write!(
            out,
            r#"<li class="g-setup__next"><section class="g-panel g-setup__cols"><div class="g-stack"><p class="t-tag g-caps g-muted">Step {} of 5</p><h2 class="t-md">{}</h2><p class="t-lead">{}</p><p class="t-body g-muted g-setup__why">{}</p>{}</div><div class="g-stack" style="align-content: start"><p class="t-tag g-caps g-muted">Done when</p><dl class="g-points">{points}</dl></div></section></li>"#,
            i + 1,
            s.title,
            esc(&s.lead),
            s.why,
            acts(&format!(
                r#"<a class="g-btn t-body" href="{}">{}</a>{}"#,
                s.action.1,
                s.action.0,
                docs(s.guide.0, s.guide.1)
            ))
        );
    }
    out + "</ol>"
}

// ---------------------------------------------------------------- pages

/// The welcome: no nav yet, nothing in it would have data.
fn welcome(f: &Facts, may: bool) -> String {
    let inner = format!(
        r#"<div class="g-focus"><div class="g-focus__top"><span class="g-nav__brand"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Gantry</span></span><span class="g-live t-small">Running at {}</span></div>{}{}{}</div>"#,
        esc(&f.base),
        motif(&["", "", "", ""], &["empty", "empty"], (2, 1), false, true),
        head(
            "What do you want to start with?",
            "Pick one. You get a short checklist for it, and the console fills in as each step happens. The rest stays one click away.",
            ""
        ),
        pick_form(None, may)
    );
    crate::html::document("Start here", &inner)
}

struct View<'a> {
    kept: &'a Kept,
    track: Option<Track>,
    tool: String,
    made: Option<&'a Made>,
    watch_token: Option<&'a str>,
    error: String,
    picking: bool,
}

/// What state.json answers and the page carries: the track and each step's state. A change reloads the page.
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

fn render(console: &Console, admin: &Admin, uri: &Uri, f: &Facts, v: &View<'_>) -> Response {
    let may = may_choose(admin);
    let problem = if f.problem.is_empty() {
        String::new()
    } else {
        pages::alert(&esc(&f.problem))
    };
    let Some(track) = v.track else {
        // An empty install with nothing chosen and nothing skipped opens on the welcome.
        if !v.kept.skipped && !v.picking && f.requests.is_empty() && f.people.is_empty() {
            return page(StatusCode::OK, welcome(f, may));
        }
        let main = format!(
            "{}{problem}{}{}",
            observe_banner(f),
            head(
                "Start here",
                "Pick what to start with. You get a short checklist for it, and each step turns done when the gateway sees it happen.",
                ""
            ),
            pick_form(v.kept.choice, may)
        );
        return console.page(StatusCode::OK, admin, "Start here", uri, &main);
    };
    let ctx = Ctx {
        f,
        admin,
        track,
        tool: v.tool.clone(),
        made: v.made,
        watch_token: v.watch_token,
        error: v.error.clone(),
        policy: policy_text(console),
    };
    let list = steps(&ctx);
    let st = states(&list);
    let done = st.iter().filter(|s| **s == "done").count();
    let finished = complete(&list);
    let change = if may {
        r#"<a class="g-btn g-btn--quiet t-body" href="/console/start?pick=1">Change what to start with</a>"#.to_string()
    } else {
        String::new()
    };
    let others = || -> String {
        let rows: String = TRACKS
            .iter()
            .filter(|t| **t != track)
            .map(|t| {
                let start = if may {
                    format!(
                        r#"<form method="post" action="/console/start/pick"><input type="hidden" name="choice" value="{}"><button class="g-btn g-btn--quiet g-btn--sm t-small" type="submit">Start</button></form>"#,
                        t.id()
                    )
                } else {
                    format!(r#"<a class="g-btn g-btn--quiet g-btn--sm t-small" href="/console/start?track={}">Show</a>"#, t.id())
                };
                format!(
                    r#"<div class="g-row"><div class="g-row__main"><span class="g-pick__head"><span class="t-body-strong">{}</span>{}</span><span class="g-row__meta t-small">{} steps. Covers {}.</span></div><div class="g-row__end">{start}</div></div>"#,
                    t.name(),
                    if t.enterprise() { ent() } else { String::new() },
                    t.steps(),
                    t.covers()
                )
            })
            .collect();
        format!(
            r#"<div class="g-stack"><h2 class="t-sm">Also start with</h2><div class="g-list">{rows}</div></div>"#
        )
    };
    let viewing_other = v.kept.choice != Some(track);
    let main = if finished
        && v.kept.steps
        && !viewing_other
        && Form::of(uri).get("view") != "checklist"
    {
        let folded = format!(
            r#"<div class="g-row"><span class="g-check__mark" style="background: var(--inverse); color: var(--on-inverse)" aria-hidden="true"><svg class="g-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg></span><div class="g-row__main"><span class="t-body-strong">{}</span><span class="g-row__meta t-small">{done} of {} done. {} people sent requests through Gantry.</span></div><div class="g-row__end"><a class="g-btn g-btn--quiet g-btn--sm t-small" href="/console/start?view=checklist">Show the steps</a></div></div>"#,
            track.name(),
            list.len(),
            f.senders().len()
        );
        format!(
            "{}{problem}{}{folded}{}{}",
            observe_banner(f),
            head(
                "Start here",
                &format!(
                    "{} is set up. Gantry now checks the five steps of a rollout against its own records.",
                    track.name()
                ),
                ""
            ),
            strip(f, track),
            others()
        )
    } else {
        // The first rows are records: shown only to someone who may see records.
        let traffic = admin.may(Permission::SeeRecords)
            && matches!(track, Track::Coding | Track::Apps | Track::Limit)
            && list.get(1).is_some_and(|s| s.done)
            && !finished;
        let sig = signature(Some(track), &st, finished);
        let poll = if st.contains(&"listening") {
            format!(r#" data-start-poll="{}""#, esc(&sig))
        } else {
            String::new()
        };
        let lead = if traffic {
            format!(
                "Your first requests arrived. {}: {done} of {} done.",
                track.name(),
                list.len()
            )
        } else {
            format!(
                "{}: {done} of {} done. Each step turns done when the gateway sees it happen.",
                track.name(),
                list.len()
            )
        };
        let viewing = if viewing_other && v.kept.choice.is_some() {
            format!(
                r#"<p class="t-small g-muted">Showing {}. This install started with {}.</p>"#,
                track.name(),
                v.kept.choice.map_or("", Track::name)
            )
        } else {
            String::new()
        };
        let body = if traffic {
            format!(
                r#"{}<div class="g-stack"><h2 class="t-sm">Next step</h2>{}</div>"#,
                first_data(f),
                checklist(&list, &st, true)
            )
        } else {
            checklist(&list, &st, false)
        };
        let banner = if finished && !viewing_other {
            format!(
                r#"<form class="g-banner" method="post" action="/console/start/pick"><span class="t-body">All required steps are done. Next: the five steps of a rollout, starting with the one this choice leaves open.</span><input type="hidden" name="steps" value="1"><button class="g-btn t-body" type="submit">Show the five steps</button></form>"#
            )
        } else {
            String::new()
        };
        format!(
            r#"<div class="g-stack" style="gap: var(--space-6)"{poll}>{}{problem}{}{viewing}{body}{banner}{}</div>"#,
            observe_banner(f),
            head("Start here", &lead, &change),
            if finished { others() } else { String::new() }
        )
    };
    console.page(StatusCode::OK, admin, "Start here", uri, &main)
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
        error: String::new(),
        picking,
    }
}

async fn start_page(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let mut f = facts(&console, &admin, origin(&headers, &uri, &tls)).await;
    let kept = match read_kept(&console) {
        Ok(kept) => kept,
        Err(err) => {
            f.problem = err;
            Kept::default()
        }
    };
    let query = Form::of(&uri);
    let view = view_of(&kept, &query);
    render(&console, &admin, &uri, &f, &view)
}

/// The state of the shown checklist, for the page's script: it reloads when `signature` changes.
async fn state_json(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "application/json")],
            json!({ "error": { "code": "not_signed_in", "message": "Sign in to the console again." } }).to_string(),
        )
            .into_response();
    };
    let f = facts(&console, &admin, origin(&headers, &uri, &tls)).await;
    let kept = read_kept(&console).unwrap_or_default();
    let query = Form::of(&uri);
    let track = Track::of(query.get("track")).or(kept.choice);
    let (states, finished) = match track {
        Some(track) => {
            let ctx = Ctx {
                f: &f,
                admin: &admin,
                track,
                tool: String::new(),
                made: None,
                watch_token: None,
                error: String::new(),
                policy: String::new(),
            };
            let list = steps(&ctx);
            (states(&list), complete(&list))
        }
        None => (Vec::new(), false),
    };
    let body = json!({
        "track": track.map(Track::id),
        "steps": states,
        "complete": finished,
        "signature": signature(track, &states, finished),
    });
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

/// Keeps the starting choice, a skip, or that the five steps were asked for.
async fn pick(State(console): State<Console>, headers: HeaderMap, body: String) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    if !may_choose(&admin) {
        read_only(&console, &admin, "start_choice").await;
        return redirect(crate::HOME);
    }
    let form = Form::parse(&body);
    let mut kept = read_kept(&console).unwrap_or_default();
    let target = if form.get("steps") == "1" {
        kept.steps = true;
        json!({ "steps": true })
    } else if form.get("skip") == "1" {
        kept.skipped = true;
        json!({ "skipped": true })
    } else {
        let Some(track) = Track::of(form.get("choice")) else {
            return redirect("/console/start?pick=1");
        };
        if kept.choice != Some(track) {
            kept.steps = false;
        }
        kept.choice = Some(track);
        json!({ "choice": track.id() })
    };
    let act = Act {
        action: "start_choice",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target,
    };
    if record(&console, &act, None, None).await.is_err() {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::notice("Not done", NOT_RECORDED, crate::HOME, "Back to Start here"),
        );
    }
    if let Err(err) = write_kept(&console, &kept) {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::notice("Not kept", &esc(&err), crate::HOME, "Back to Start here"),
        );
    }
    redirect(crate::HOME)
}

/// Makes a key from a step, through the People page's own issue flow, and shows it once on the checklist.
async fn make_key(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let (name, team) = (
        form.get("name").trim().to_string(),
        form.get("team").trim().to_string(),
    );
    let workload = form.get("kind") == "workload";
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
    let kept = read_kept(&console).unwrap_or_default();
    let error = if !admin.may(Permission::IssueKeys) {
        read_only(&console, &admin, "issue_key").await;
        Some("Your role cannot make keys. Ask an admin to make this one.".to_string())
    } else if !admin.covers(&attributes.org, &team, attributes.customer.as_deref()) {
        read_only(&console, &admin, "issue_key").await;
        Some(format!(
            "Your role keeps you to team{} {}: make the key in one of them.",
            if admin.teams.len() == 1 { "" } else { "s" },
            admin.teams.join(", ")
        ))
    } else {
        None
    };
    let result = match error {
        Some(e) => Err(e),
        None => crate::issued(&console, &admin, &name, &team, attributes).await,
    };
    let mut f = facts(&console, &admin, origin(&headers, &uri, &tls)).await;
    if let Err(err) = read_kept(&console) {
        f.problem = err;
    }
    let mut view = view_of(&kept, &Form(Vec::new()));
    let made;
    let status;
    match result {
        Ok((key, _)) => {
            made = Made { name, team, key };
            view.made = Some(&made);
            status = StatusCode::OK;
        }
        Err(err) => {
            view.error = err;
            status = StatusCode::BAD_REQUEST;
        }
    }
    let mut response = render(&console, &admin, &uri, &f, &view);
    *response.status_mut() = status;
    response
}

/// Makes a watch token through the binary's watch flow and fills it into the settings block, shown once.
async fn make_watch_token(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let team = Form::parse(&body).get("team").trim().to_string();
    let result = match &console.0.watch {
        None => Err(
            "Watch mode is not on: it needs a license that includes watch and a store. See step 1."
                .to_string(),
        ),
        Some(watch) => (watch.token)(console.clone(), admin.clone(), team).await,
    };
    let f = facts(&console, &admin, origin(&headers, &uri, &tls)).await;
    let mut kept = read_kept(&console).unwrap_or_default();
    // The token belongs to the watch checklist, whatever was chosen.
    kept.choice = kept.choice.or(Some(Track::Watch));
    let mut view = view_of(&kept, &Form(Vec::new()));
    view.track = Some(Track::Watch);
    let token;
    let status = match result {
        Ok(t) => {
            token = t;
            view.watch_token = Some(&token);
            StatusCode::OK
        }
        Err(err) => {
            view.error = err;
            StatusCode::BAD_REQUEST
        }
    };
    let mut response = render(&console, &admin, &uri, &f, &view);
    *response.status_mut() = status;
    response
}

// ---------------------------------------------------------------- empty pages

/// What fills a console page, the one action that does it (the Start here step), and its docs page.
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
        "Point a tool at Gantry",
        "/console/start?track=coding#step-2",
    );
    let key = ("Make a key", "/console/start?track=coding#step-1");
    Some(match page {
        "Requests" => Empty {
            title: "No requests yet",
            body: format!(
                "Point one tool at {} with a Gantry key. Each request shows here as one row with its person, model and cost.",
                esc(base)
            ),
            action: key,
            docs: "/integrations/coding-tools/",
            extra: command("empty-copy", &format!("export ANTHROPIC_BASE_URL={base}")),
        },
        "Analytics" => Empty {
            title: "Nothing to rank yet",
            body: "Analytics ranks requests by person, team, tool and model. It starts with the first request through Gantry and draws a trend after a day.".into(),
            action: point,
            docs: "/operations/request-log/",
            extra: String::new(),
        },
        "Spend" => Empty {
            title: "No spend and no budgets yet",
            body: "Spend counts from the first request through Gantry. Add a budget now and it counts against it from that request. Observe mode records what it would refuse.".into(),
            action: ("Add a budget", "/console/start?track=limit#step-3"),
            docs: "/governance/budgets-and-rate-limits/",
            extra: code(&[
                (1, crate::html::yaml_line("limits:"), "add"),
                (2, crate::html::yaml_line(r#"  - { team: "*", budget: { usd: 500, per: month } }"#), "add"),
            ]),
        },
        "People and workloads" => Empty {
            title: "Only your admin key so far",
            body: "Make a key for each person or workload, so every request carries a name and a team. Or connect single sign-on and people make their own.".into(),
            action: key,
            docs: "/governance/keys/",
            extra: command("empty-copy", &format!("gantry key new sarah.miller --team platform --url {base}")),
        },
        "Teams" => Empty {
            title: "No teams yet",
            body: "A team is set when you make a key, such as team payments for mike.johnson. Each team shows here with its people, its rule and its budget.".into(),
            action: ("Make a key with a team", "/console/start?track=coding#step-1"),
            docs: "/governance/teams/",
            extra: String::new(),
        },
        "Policy" => Empty {
            title: "One rule lets everyone in",
            body: "This is the policy Gantry wrote at first start: every key may use every model, and observe mode blocks nothing. Add a budget or a guardrail when you are ready.".into(),
            action: ("Edit the policy", "/console/start?track=limit#step-3"),
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
                &format!("GANTRY_DEVICE_TOKEN=gantry_dev_... gantry device --control-plane {base} --dry-run"),
            ),
        },
        "Watch" => Empty {
            title: "No Claude Code telemetry yet",
            body: "Make a watch token and paste the settings block into claude.ai, Organization settings, Claude Code, Managed settings. People show here within a few minutes of their next session.".into(),
            action: ("Make a watch token", "/console/start?track=watch#step-2"),
            docs: "/integrations/claude-team/",
            extra: String::new(),
        },
        "MCP approvals" => Empty {
            title: "No MCP servers behind Gantry",
            body: format!(
                "Add a server under mcp: in the policy and point the agent at {}/mcp. A tool call that needs an admin's approval waits here.",
                esc(base)
            ),
            action: ("Add an MCP server", "/console/start?track=mcp#step-1"),
            docs: "/governance/mcp-gateway/",
            extra: String::new(),
        },
        "Audit log" => Empty {
            title: "Only setup records so far",
            body: "Every request through Gantry adds a record here, allowed or refused, chained to the one before it. Send one request to see the first.".into(),
            action: point,
            docs: "/governance/audit-log/",
            extra: String::new(),
        },
        _ => return None,
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
            ..Step::new("t", done, String::new(), "", "")
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
}
