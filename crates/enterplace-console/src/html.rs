//! The markup of the approved screens, as the helpers of design-screens/build.py write it.
//! Every class name here is one the design system's bundle.css defines. Nothing here sets a color or a size.

use std::fmt::Write as _;

/// Text made safe to put in HTML, in an element or a quoted attribute.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Text made safe to put in a URL query value.
pub fn enc(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// "140,028".
pub fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Lucide icons (ISC license), the one icon set of the system.
pub fn icon(name: &str) -> String {
    let paths = match name {
        "search" => r#"<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>"#,
        "left" => r#"<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>"#,
        "right" => r#"<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>"#,
        "down" => r#"<path d="m6 9 6 6 6-6"/>"#,
        "menu" => r#"<path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/>"#,
        "copy" => {
            r#"<rect x="8" y="8" width="14" height="14" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>"#
        }
        _ => r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#,
    };
    format!(r#"<svg class="g-icon" viewBox="0 0 24 24" aria-hidden="true">{paths}</svg>"#)
}

/// A verdict or a label. `detail` is escaped here, `word` is fixed text.
pub fn tag(kind: &str, word: &str, detail: &str) -> String {
    let cls = if kind.is_empty() {
        "g-tag".to_string()
    } else {
        format!("g-tag g-tag--{kind}")
    };
    if detail.is_empty() {
        return format!(r#"<span class="{cls} t-tag">{word}</span>"#);
    }
    format!(
        r#"<span class="{cls}"><span class="t-tag">{word}</span><span class="t-mono-sm">{}</span></span>"#,
        esc(detail)
    )
}

fn btn_class(kind: &str, small: bool) -> String {
    let kind = if kind.is_empty() {
        String::new()
    } else {
        format!(" g-btn--{kind}")
    };
    let size = if small {
        " g-btn--sm t-small"
    } else {
        " t-body"
    };
    format!("g-btn{kind}{size}")
}

/// The link that closes a dialog or a sheet: Escape follows it.
pub fn close_link(label: &str, kind: &str, href: &str) -> String {
    format!(
        r#"<a class="{}" href="{href}" data-close>{label}</a>"#,
        btn_class(kind, false)
    )
}

/// A button that is a link. `href` is used as given and must already be safe.
pub fn link(label: &str, kind: &str, href: &str, small: bool) -> String {
    format!(
        r#"<a class="{}" href="{href}">{label}</a>"#,
        btn_class(kind, small)
    )
}

/// A button. `attrs` starts with a space.
pub fn button(label: &str, kind: &str, kind_attr: &str, attrs: &str) -> String {
    format!(
        r#"<button class="{}" type="{kind_attr}"{attrs}>{label}</button>"#,
        btn_class(kind, false)
    )
}

pub fn head(title: &str, lead: &str, actions: &str) -> String {
    let actions = if actions.is_empty() {
        String::new()
    } else {
        format!("\n<div class=\"g-head__actions\">{actions}</div>")
    };
    format!(
        "<header class=\"g-head\">\n<h1 class=\"g-head__title t-md\">{title}</h1>\n<p class=\"g-head__lead t-small g-muted\">{lead}</p>{actions}\n</header>"
    )
}

/// Links between pages that share one nav item, such as the MCP pages: (href, label), the current one marked.
pub fn page_tabs(pages: &[(&str, &str)], current: &str) -> String {
    let tabs: String = pages
        .iter()
        .map(|(href, label)| {
            let here = if *label == current {
                r#" aria-pressed="true""#
            } else {
                ""
            };
            format!(
                r#"<a class="g-tab t-small" href="{}"{here}>{}</a>"#,
                esc(href),
                esc(label)
            )
        })
        .collect();
    format!(r#"<nav class="g-tabs" aria-label="Pages">{tabs}</nav>"#)
}

/// Label and value pairs for one record. Values are markup: the caller escapes text, so a value can hold a tag.
pub fn facts(pairs: &[(&str, String)]) -> String {
    let mut out = String::from(r#"<dl class="g-facts">"#);
    for (k, v) in pairs {
        let _ = write!(
            out,
            r#"<dt class="t-tag">{k}</dt><dd class="t-mono-sm">{v}</dd>"#
        );
    }
    out + "</dl>"
}

/// The count line and the two arrows. An arrow with nowhere to go is shown disabled.
pub fn pager(text: &str, newer: (&str, Option<String>), older: (&str, Option<String>)) -> String {
    let arrow = |(label, href): (&str, Option<String>), name: &str| match href {
        Some(href) => format!(
            r#"<a class="g-btn g-btn--quiet g-btn--icon" href="{href}" aria-label="{label}">{}</a>"#,
            icon(name)
        ),
        None => format!(
            r#"<button class="g-btn g-btn--quiet g-btn--icon" type="button" aria-label="{label}" disabled>{}</button>"#,
            icon(name)
        ),
    };
    format!(
        r#"<div class="g-pager"><span class="t-small g-muted">{text}</span><div class="g-pager__buttons">{}{}</div></div>"#,
        arrow(newer, "left"),
        arrow(older, "right")
    )
}

/// One thing in a short list. `ident` sets the title in mono, for a name or a file.
pub fn row(title: &str, meta: &str, end: &str, ident: bool) -> String {
    let style = if ident { "t-mono-lg" } else { "t-sm" };
    let tail = if end.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="g-row__end">{end}</div>"#)
    };
    format!(
        r#"<div class="g-row"><div class="g-row__main"><span class="{style}">{title}</span><span class="g-row__meta t-small">{meta}</span></div>{tail}</div>"#
    )
}

/// Lines of a policy file: (number, text already marked up, kind), kind being "", "hit", "error", "add" or "del".
/// A kind of "note" is a message under the line before it.
pub fn code(lines: &[(usize, String, &str)]) -> String {
    let mut out = String::from("<div class=\"g-code t-mono\">\n");
    for (n, text, kind) in lines {
        if *kind == "note" {
            let _ = writeln!(out, r#"<div class="g-code__note t-small">{text}</div>"#);
            continue;
        }
        let cls = if kind.is_empty() {
            String::new()
        } else {
            format!(" g-code__line--{kind}")
        };
        let mark = match *kind {
            "add" => "+",
            "del" => "-",
            _ => "",
        };
        // A diff shows a line number twice, once removed and once added: only the file view needs an anchor.
        let anchor = if mark.is_empty() {
            format!(r#" id="line-{n}""#)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            r#"<div class="g-code__line{cls}"{anchor}><span class="g-code__n">{n}</span><span>{mark}</span><span>{text}</span></div>"#
        );
    }
    out + "</div>"
}

/// One line of YAML, marked up as the designs mark it: comments muted, values muted after their key.
pub fn yaml_line(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return format!(r#"<span class="g-code__c">{}</span>"#, esc(line));
    }
    match line.split_once(": ") {
        Some((key, value)) => format!(
            r#"{}: <span class="g-code__v">{}</span>"#,
            esc(key),
            esc(value)
        ),
        None => esc(line),
    }
}

/// Requests are discs: `incoming` and `passed` name each disc ("", "flame", "lime", "empty").
pub fn motif(
    incoming: &[&str],
    passed: &[&str],
    cols: (usize, usize),
    closed: bool,
    small: bool,
) -> String {
    let (cols_in, cols_out) = cols;
    let grid = |cells: &[&str], cols: usize| {
        let discs: String = cells
            .iter()
            .map(|c| {
                if c.is_empty() {
                    r#"<span class="g-disc"></span>"#.to_string()
                } else {
                    format!(r#"<span class="g-disc g-disc--{c}"></span>"#)
                }
            })
            .collect();
        format!(r#"<div class="g-motif__grid" style="--g-cols: {cols}">{discs}</div>"#)
    };
    let gate = if closed {
        r#"<span class="g-gate g-gate--closed"></span>"#
    } else {
        r#"<span class="g-gate"></span>"#
    };
    format!(
        r#"<div class="g-motif{}" aria-hidden="true">{}{gate}{}</div>"#,
        if small { " g-motif--sm" } else { "" },
        grid(incoming, cols_in),
        grid(passed, cols_out)
    )
}

/// An empty, failed or not-permitted state of a page.
pub fn empty(picture: &str, title: &str, body: &str, action: &str) -> String {
    format!(
        r#"<div class="g-empty">{picture}<h2 class="g-empty__title t-md">{title}</h2><p class="g-empty__body t-body">{body}</p>{action}</div>"#
    )
}

/// A whole page. The theme is set from the browser's preference by console.js before the first paint.
/// The empty icon stops the browser asking the gateway for /favicon.ico, which it would record as a refused request.
pub fn document(title: &str, body: &str) -> String {
    document_with(title, "", body)
}

/// A whole page with more in its head, such as a refresh.
pub fn document_with(title: &str, head: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}, Enterplace</title>
<link rel="icon" href="data:,">{head}
<script src="/console/assets/console.js"></script>
<link rel="stylesheet" href="/console/assets/tokens.css">
<link rel="stylesheet" href="/console/assets/bundle.css">
<link rel="stylesheet" href="/console/assets/console.css">
</head>
<body>
{body}
</body>
</html>
"#
    )
}

/// What an embedding binary added to every page, set per request by the console (see `crate::Extension`).
#[derive(Default)]
pub(crate) struct Extra {
    pub nav: Vec<(String, String)>,
    pub sign_in: Option<(String, String)>,
}

tokio::task_local! {
    pub(crate) static EXTRA: std::sync::Arc<Extra>;
    /// The policy in force is in observe mode: every page says so in one line.
    pub(crate) static OBSERVE: bool;
}

/// One line at the top of every page in observe mode, so nobody reads a page as if rules were stopping requests.
fn observe_line() -> &'static str {
    if OBSERVE.try_with(|o| *o).unwrap_or(false) {
        r#"<p class="t-small g-muted" style="margin: 0">Observe mode: rules only record. <a href="/console/start?track=limit">Turn on enforcement</a></p>
"#
    } else {
        ""
    }
}

/// The nav: Start here, then the pages by what they are for. Each item is (href, label shown, the labels of the
/// pages it stands for); a page is marked by the label it passes as `current`. Teams lives under People, and the
/// pages a binary adds (MCP, deployments, enterprise) go under Tools.
/// A nav item: its href, the label shown, and the labels of the pages it stands for.
type Item = (&'static str, &'static str, &'static [&'static str]);

const GROUPS: [(&str, &[Item]); 3] = [
    ("", &[("/console/start", "Start here", &["Start here"])]),
    (
        "Activity",
        &[
            ("/console/requests", "Requests", &["Requests"]),
            ("/console/audit", "Audit log", &["Audit log"]),
            ("/console/analytics", "Analytics", &["Analytics"]),
            ("/console/spend", "Spend", &["Spend"]),
        ],
    ),
    (
        "Access",
        &[
            (
                "/console/people",
                "People",
                &["People and workloads", "Teams"],
            ),
            ("/console/policy", "Policy", &["Policy"]),
            ("/console/models", "Models", &["Models"]),
            (
                "/console/credentials",
                "Providers",
                &["Provider credentials"],
            ),
        ],
    ),
];

/// The pages a binary adds, folded the same way: the three MCP pages are one item, linking to the first of them
/// the binary added (the first is the key here, not a link).
const FOLDED: [Item; 1] = [(
    "/console/mcp/tools",
    "MCP servers",
    &["MCP tools", "MCP approvals", "MCP sessions"],
)];

fn nav_links(current: &str, class: &str, extra: &str) -> String {
    let link = |href: &str, label: &str, marks: bool| {
        let here = if marks { r#" aria-current="page""# } else { "" };
        format!(
            r#"<a class="{class} t-body" href="{}"{here}{extra}>{}</a>"#,
            esc(href),
            esc(label)
        )
    };
    let group = |name: &str| format!(r#"<span class="g-nav__group t-tag g-caps">{name}</span>"#);
    let mut out = Vec::new();
    for (name, items) in GROUPS {
        if !name.is_empty() {
            out.push(group(name));
        }
        for (href, label, pages) in items {
            out.push(link(href, label, pages.contains(&current)));
        }
    }
    let added = EXTRA.try_with(|e| e.nav.clone()).unwrap_or_default();
    if !added.is_empty() {
        out.push(group("Tools"));
    }
    let mut folded_shown = Vec::new();
    for (href, label) in &added {
        match FOLDED
            .iter()
            .find(|(_, _, pages)| pages.contains(&label.as_str()))
        {
            Some((key, shown, pages)) => {
                if !folded_shown.contains(key) {
                    folded_shown.push(*key);
                    out.push(link(href, shown, pages.contains(&current)));
                }
            }
            None => out.push(link(href, label, label == current)),
        }
    }
    out.join("\n")
}

/// `admin` is "name, role": the name on one line and the role under it, so a long email never splits the role.
/// The built-in admin is named after its role, and "admin" twice reads as a glitch: the role shows only when it
/// adds something.
fn signed_in(admin: &str) -> String {
    let (name, role) = admin.rsplit_once(", ").unwrap_or((admin, ""));
    let role = if role.is_empty() || role == name {
        String::new()
    } else {
        format!(r#"<span class="t-small g-muted">{}</span>"#, esc(role))
    };
    format!(
        r#"<span class="g-live t-small" data-live="checking" data-live-last-request="">Checking requests</span><span class="g-stack" style="gap: 0"><span class="t-mono g-muted">{}</span>{role}</span><a class="t-small" href="/console/sign-out">Sign out</a>"#,
        esc(name),
    )
}

/// The app shell: the nav beside the page, and an overlay over both. `menu` opens the phone menu sheet.
pub fn shell(
    current: &str,
    admin: &str,
    here: &str,
    main: &str,
    overlay: &str,
    menu: bool,
) -> String {
    // A page served by a nested router knows its path without the prefix (`/start`): the Menu link of Start here
    // went to /start?menu=1, which is no console page, and a phone got a JSON refusal.
    let here = if here.starts_with("/console") {
        here.to_string()
    } else {
        format!("/console{here}")
    };
    let here = here.as_str();
    let sheet = if menu {
        format!(
            r#"<div class="g-scrim g-menu-sheet">
<nav class="g-sheet" aria-label="Menu">
<div class="g-pager"><span class="t-md">Menu</span><a class="g-btn g-btn--quiet g-btn--icon" href="{here}" aria-label="Close the menu">{}</a></div>
<div class="g-stack" style="gap: var(--space-1)">
{}
</div>
<div class="g-toolbar" style="gap: var(--space-2) var(--space-4)">{}</div>
</nav>
</div>"#,
            icon("close"),
            nav_links(current, "g-menu__item", r#" style="text-decoration: none""#),
            signed_in(admin)
        )
    } else {
        String::new()
    };
    format!(
        r##"<a class="g-btn g-btn--sm t-small g-skip" href="#main">Skip to the page</a>
<div class="g-shell">
<nav class="g-nav g-nav--side" aria-label="App">
<a class="g-nav__brand" href="/console/start"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Enterplace</span></a>
{}
<div class="g-nav__foot">{}</div>
<a class="g-nav__menu g-btn g-btn--quiet g-btn--sm t-small" href="{here}?menu=1">{}Menu</a>
</nav>
<main class="g-shell__main" id="main" tabindex="-1">
{observe}{main}
</main>
{overlay}{sheet}
</div>"##,
        nav_links(current, "g-nav__item", ""),
        signed_in(admin),
        icon("menu"),
        observe = observe_line(),
    )
}

/// A dialog on a scrim, as the KillAll and PolicySave screens draw it. `inner` holds the fields and the actions.
pub fn dialog(id: &str, title: &str, body: &str, inner: &str) -> String {
    format!(
        r#"<div class="g-scrim">
<div class="g-dialog" role="dialog" aria-modal="true" aria-labelledby="{id}">
<h2 class="g-dialog__title t-md" id="{id}">{title}</h2>
<p class="g-dialog__body t-body">{body}</p>
{inner}
</div>
</div>"#
    )
}

/// A text field. With an error it is marked invalid and the error is read with it. `extra` starts with a space.
pub struct Field<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub label: &'a str,
    pub value: &'a str,
    /// For a key or a name a machine reads: set in mono.
    pub mono: bool,
    pub extra: &'a str,
    pub hint: &'a str,
    pub error: &'a str,
}

pub fn field(f: &Field<'_>) -> String {
    let id = f.id;
    let (state, note) = if !f.error.is_empty() {
        (
            format!(r#" aria-invalid="true" aria-describedby="{id}-error""#),
            format!(
                r#"<span class="g-field__error t-small" id="{id}-error">{}</span>"#,
                f.error
            ),
        )
    } else if !f.hint.is_empty() {
        (
            String::new(),
            format!(r#"<span class="g-field__hint t-small">{}</span>"#, f.hint),
        )
    } else {
        (String::new(), String::new())
    };
    // A bare "sarah.miller" in an empty field reads as a value already filled in, to people and to screen readers
    // alike. Every field passes through here, so the prefix is added once rather than in each page's placeholder.
    let extra = match f.extra.split_once(r#" placeholder=""#) {
        Some((before, after)) if !after.starts_with("e.g. ") => {
            format!(r#"{before} placeholder="e.g. {after}"#)
        }
        _ => f.extra.to_string(),
    };
    format!(
        r#"<div class="g-field"><label class="g-field__label t-tag g-caps" for="{id}">{}</label><input class="g-input {}" id="{id}" name="{}" value="{}"{}{state}>{note}</div>"#,
        f.label,
        if f.mono { "t-mono" } else { "t-body" },
        f.name,
        esc(f.value),
        extra
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_nav_is_grouped_and_a_page_folded_into_another_marks_it() {
        let nav = super::nav_links("Teams", "g-nav__item", "");
        // Three groups, in this order, with Start here above them.
        let at = |s: &str| nav.find(s).unwrap_or(usize::MAX);
        assert!(
            at(">Start here<") < at(">Activity<") && at(">Activity<") < at(">Access<"),
            "{nav}"
        );
        assert!(
            at(">Requests<") < at(">Audit log<") && at(">Audit log<") < at(">Access<"),
            "{nav}"
        );
        // Teams has no item of its own: People is marked while it is open.
        assert!(
            nav.contains(r#"href="/console/people" aria-current="page">People<"#),
            "{nav}"
        );
        assert!(
            !nav.contains(">Teams<") && nav.contains(">Providers<"),
            "{nav}"
        );
    }

    #[test]
    fn the_menu_link_of_a_nested_page_stays_in_the_console() {
        let page = super::shell("/console/start", "admin, admin", "/start", "", "", false);
        assert!(page.contains(r#"href="/console/start?menu=1""#), "{page}");
        let page = super::shell(
            "/console/audit",
            "admin, admin",
            "/console/audit",
            "",
            "",
            false,
        );
        assert!(page.contains(r#"href="/console/audit?menu=1""#), "{page}");
    }

    use super::*;

    #[test]
    fn the_nav_foot_shows_the_role_only_when_it_differs_from_the_name() {
        let foot = signed_in("admin, admin");
        assert_eq!(foot.matches(">admin<").count(), 1, "{foot}");
        let foot = signed_in("dana@example.com, admin");
        assert!(
            foot.contains(">dana@example.com<") && foot.contains(">admin<"),
            "{foot}"
        );
        // The name is never the 12px grey: muted text is 13px at least.
        assert!(!foot.contains("t-mono-sm"), "{foot}");
    }

    #[test]
    fn a_field_placeholder_reads_as_an_example() {
        let f = |extra| {
            field(&Field {
                id: "n",
                name: "n",
                label: "Name",
                value: "",
                mono: true,
                extra,
                hint: "",
                error: "",
            })
        };
        let html = f(r#" required placeholder="sarah.miller" autocomplete="off""#);
        assert!(
            html.contains(r#"placeholder="e.g. sarah.miller""#),
            "{html}"
        );
        // Already an example, or no placeholder at all: left as written.
        let html = f(r#" placeholder="e.g. payments""#);
        assert!(html.contains(r#"placeholder="e.g. payments""#), "{html}");
        assert!(!f(" required").contains("placeholder"));
    }

    #[test]
    fn text_is_escaped_and_encoded() {
        assert_eq!(
            esc(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(enc("maya cohen/&"), "maya%20cohen%2F%26");
        assert_eq!(thousands(140_028), "140,028");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000_000), "1,000,000");
    }
}
