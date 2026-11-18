//! The pages, each built from the markup of its approved screen in design-screens/build.py.

use std::{collections::HashMap, fmt::Write as _, path::Path};

use enterplace_core::{
    config::Loaded,
    kill::Kill,
    policy::{Models, Who},
};

use crate::{
    Form,
    figures::money,
    html::{
        Field, button, code, document, empty, enc, esc, field, head, link, motif, row, shell, tag,
        yaml_line,
    },
};

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

// ---------------------------------------------------------------- shared with the audit log in the app

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

/// A refusal code in words, as a tag says it: "unknown key", not `unknown_key`.
pub(crate) fn code_words(code: &str) -> String {
    match code {
        "killed" => "kill switch".into(),
        other => other.replace('_', " "),
    }
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

/// The lines that differ between two versions of the policy, with one line around each change.
// ponytail: a longest-common-subsequence table, lines squared. Policy files are a few hundred lines at most.
pub(crate) fn diff(old: &str, new: &str) -> Vec<(usize, String, &'static str)> {
    enterplace_core::versions::diff(old, new)
        .into_iter()
        .map(|(n, line, kind)| (n, yaml_line(&line), kind))
        .collect()
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

/// Month names, shared with the Spend API.
pub(crate) const MONTHS: [&str; 12] = [
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

pub(crate) fn days_in(year: u32, month: u32) -> usize {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Where a usage record's price came from, from its `price_source`.
pub(crate) fn price_word(source: &str) -> String {
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
    use crate::figures::time_full;

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
