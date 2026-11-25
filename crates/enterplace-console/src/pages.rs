//! The pages, each built from the markup of its approved screen in design-screens/build.py.

use enterplace_core::kill::Kill;

use crate::{
    Form,
    html::{Field, button, document, empty, enc, esc, field, link, motif, shell},
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

/// The refusal code of a record in words, with the limit that refused it when one did: "rate limited, team payments
/// tokens per day 300". A limit names its scope, so whoever reads the list sees who hit what.
pub(crate) fn refusal_words(record: &serde_json::Value) -> String {
    let field = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let words = code_words(&field(record, "code"));
    let Some(applied) = record.get("applied").filter(|a| a.is_object()) else {
        return words;
    };
    let scope = match field(applied, "scope").split_once(':') {
        Some((kind, name)) => format!("{} {name}", kind.replace('_', " ")),
        None if field(applied, "of") == "global" => "everyone".to_string(),
        None => field(applied, "of"),
    };
    let limit = field(applied, "limit");
    let what = match limit.as_str() {
        "rpm" => "requests per minute",
        "rph" => "requests per hour",
        "rpd" => "requests per day",
        "tpm" => "tokens per minute",
        "tpd" => "tokens per day",
        "parallel" | "max_parallel" => "requests in flight",
        "budget" => "budget",
        other => other,
    };
    let value = match applied.get("value") {
        Some(v) if limit == "budget" => v.as_f64().map(crate::figures::money).unwrap_or_default(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    };
    let detail = [scope.as_str(), what, value.as_str()]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if detail.is_empty() {
        words
    } else {
        format!("{words}, {detail}")
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
        let kinds: Vec<&str> = enterplace_core::versions::diff("a\nb\nc\n", "a\nB\nc\n")
            .into_iter()
            .map(|(_, _, kind)| kind)
            .collect();
        assert_eq!(kinds, ["", "del", "add", ""]);
    }
}
