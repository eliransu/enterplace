"""Builds docs/*.md into a static docs site in dist/docs/, styled with the Gantry design system.

Usage: python3 scripts/docs.py [design-system folder]
The design system folder defaults to ../../design-system/project beside this repository's parent, where the
tokens, components and fonts live. Standard library only: the Markdown here is a small subset, converted below.
"""
import html, pathlib, re, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = ROOT / "dist" / "docs"
# The repository sits beside design-system, or one level deeper in a working copy.
DESIGN = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else next((p / "design-system" / "project" for p in (ROOT.parent, ROOT.parent.parent) if (p / "design-system").is_dir()), ROOT.parent / "design-system" / "project")
TOKENS = DESIGN.parent.parent / "design-screens" / "project" / "ds" / "gantry" / "tokens.css"

# (file, title, group). The order is the reading order: the nav and the next and previous links follow it.
PAGES = [
    ("index", "Overview", "Start"),
    ("quickstart", "Quickstart", "Start"),
    ("claude-code", "Claude Code", "Start"),
    ("codex", "Codex", "Start"),
    ("coding-agents", "Other coding agents", "Start"),
    # m13-1: a short label, so no nav item wraps onto a second line and runs into the next one.
    ("sdks", "SDKs", "Start"),
    ("policy", "Policy file", "Reference"),
    ("keys", "Keys", "Reference"),
    ("providers", "Providers", "Reference"),
    ("audit", "Audit log", "Reference"),
    ("refusals", "Refusal codes", "Reference"),
    ("guardrails", "Guardrails", "Reference"),
    ("guardrail-webhook", "Guardrail webhooks", "Reference"),
    ("operations", "Operations", "Run it"),
    ("kubernetes", "Kubernetes", "Run it"),
    ("observability", "Metrics and log shipping", "Run it"),
    ("security", "Security model", "Run it"),
    ("comparison", "LiteLLM and Bifrost", "Run it"),
    ("migrate-litellm", "Moving from LiteLLM", "Run it"),
]

ICONS = {  # Lucide (ISC license), the one icon set of the design system.
    "menu": '<path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/>',
    "close": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    "left": '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
    "right": '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
}


def icon(name: str) -> str:
    return f'<svg class="g-icon" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


# Only what the docs need on top of the components, and only with tokens.
DOCS_CSS = """
@font-face{font-family:"Syne";src:url("fonts/Syne-Variable.woff2") format("woff2");font-weight:400 800;font-display:swap}
@font-face{font-family:"Instrument Sans";src:url("fonts/InstrumentSans-Variable.woff2") format("woff2");font-weight:400 700;font-display:swap}
@font-face{font-family:"Fragment Mono";src:url("fonts/FragmentMono-Regular.woff2") format("woff2");font-weight:400;font-display:swap}
a{color:inherit}
.g-nav--side{position:sticky;top:var(--space-4);max-height:calc(100vh - var(--space-8));overflow-y:auto}
.d-doc{display:grid;grid-template-columns:minmax(0,1fr);gap:var(--space-4);max-width:var(--measure-wide);min-width:0}
.d-doc p,.d-doc li{overflow-wrap:break-word}
.d-doc h1,.d-doc h2,.d-doc h3,.d-doc h4,.d-doc p,.d-doc ul,.d-doc ol,.d-doc pre{margin:0}
.d-doc h2{margin-top:var(--space-8)}
.d-doc h3{margin-top:var(--space-4)}
.d-doc p,.d-doc ul,.d-doc ol{max-width:var(--measure-wide)}
.d-doc ul,.d-doc ol{display:grid;gap:var(--space-2);padding-left:var(--space-6)}
.d-doc a{text-underline-offset:var(--space-1)}
.d-doc code{font-family:var(--font-mono);font-size:0.875em;overflow-wrap:anywhere}
.d-doc .g-code{margin:0}
.d-doc .g-code__line{grid-template-columns:var(--space-10) var(--space-2) minmax(0,1fr);white-space:pre-wrap;overflow-wrap:anywhere}
.d-doc .g-code__line>span:last-child{padding-left:2ch;text-indent:-2ch}
.d-doc .g-table-wrap{border-radius:var(--radius-md);background:var(--surface);padding:var(--space-2) 0}
.d-doc .g-table td{white-space:normal;vertical-align:top}
.d-doc .g-table tbody tr:hover td{background:transparent}
.d-label{display:none;color:var(--text-muted)}
.d-doc .g-table td:first-child code{white-space:nowrap;overflow-wrap:normal}
/* m12-12: in a table of five columns a route may wrap at its space ("POST" over the path), so the table fits. */
.d-doc .d-wide td:first-child code{white-space:normal}
.d-pager{display:flex;flex-wrap:wrap;justify-content:space-between;gap:var(--space-4);margin-top:var(--space-12);padding-top:var(--space-6);border-top:var(--hairline) solid var(--line)}
.d-theme{justify-self:start}
/* m12-1: one step tighter between nav groups and above the foot, so the whole nav fits a 900px tall window. */
.g-nav--side .g-nav__group{padding-top:var(--space-2)}
.g-nav--side .g-nav__foot{margin-top:var(--space-4)}
/* m12-2: a short code span with a hyphen (--metrics) stays whole instead of breaking after the hyphen. */
.d-doc code.d-nw{white-space:nowrap;overflow-wrap:normal}
/* The current page's disc stays a disc beside a long label, instead of shrinking to an oval with it. */
.g-nav__item[aria-current="page"]::before{flex-shrink:0}
/* M12-4: a long label wraps inside the nav instead of widening it, and the nav never scrolls sideways. Each item
   keeps its 32px target; without the gap between them the whole nav fits a 900px tall window. */
.g-nav--side{overflow-x:hidden;gap:0}
.g-nav--side .g-nav__item{white-space:normal}
/* M12-5: a bare URL in prose or a table breaks anywhere rather than widening the page on a phone. */
.d-doc a{overflow-wrap:anywhere}
#menu:not(:target){display:none}
@media (max-width:720px){
  .g-nav--side{position:static;max-height:none}
  .d-doc .g-code__line{grid-template-columns:var(--space-8) var(--space-1) minmax(0,1fr)}
  .d-doc .g-table-wrap{background:transparent;padding:0}
  .d-doc .g-table--stack tr{grid-template-columns:minmax(0,1fr)}
  .d-label{display:block}
  .d-doc .g-table--stack td:first-child{font-weight:600}
  /* Stacked, the first cell has the full width: a long list of routes wraps instead of widening the page. */
  .d-doc .g-table--stack td:first-child code{white-space:normal;overflow-wrap:anywhere}
}
/* A table of five columns or more does not fit beside the nav below 1100px: it stacks, as on a phone, instead of
   scrolling sideways or squeezing a column to one word a line. */
@media (min-width:721px) and (max-width:1100px){
  .d-doc .d-wide thead{display:none}
  .d-doc .d-wide,.d-doc .d-wide tbody{display:block}
  .d-doc .d-wide tr{display:grid;grid-template-columns:minmax(0,1fr);gap:var(--space-1);padding:var(--space-3) var(--space-4);border-top:var(--hairline) solid var(--line)}
  .d-doc .d-wide tbody tr:first-child{border-top:0}
  .d-doc .d-wide td{padding:0;border:0}
  .d-doc .d-wide td:first-child{font-weight:600}
  .d-doc .d-wide .d-label{display:block}
}
"""

# The theme follows the system unless the reader picked one. ?theme= sets it for screenshots.
THEME_SCRIPT = """<script>(function(){var t=new URLSearchParams(location.search).get('theme');try{t=t||localStorage.getItem('gantry-theme')}catch(e){}
if(t!=='light'&&t!=='dark')t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.documentElement.dataset.theme=t})()</script>"""
TOGGLE_SCRIPT = """<script>document.querySelectorAll('.d-theme').forEach(function(b){b.addEventListener('click',function(){
var t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;try{localStorage.setItem('gantry-theme',t)}catch(e){}})})</script>"""


def inline(text: str) -> str:
    """Code spans, links, bare URLs and bold. Code spans are cut out first, so nothing inside them is touched."""
    out = []
    for i, part in enumerate(re.split(r"(\[`[^`]+`\]\([^)\s]+\)|`[^`]+`)", text)):
        # m13-2: a link whose text is code, [`gantry login`](keys.html#...), is a link with code in it.
        linked = re.fullmatch(r"\[`([^`]+)`\]\(([^)\s]+)\)", part) if i % 2 else None
        if linked:
            href = html.escape(linked.group(2).replace(".md", ".html"))
            out.append(f'<a href="{href}"><code>{html.escape(linked.group(1))}</code></a>')
            continue
        if i % 2:
            code = part[1:-1]
            short = "-" in code and " " not in code and len(code) <= 32
            out.append(f'<code{" class=\"d-nw\"" if short else ""}>{html.escape(code)}</code>')
            continue
        part = html.escape(part, quote=False)
        part = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: f'<a href="{m.group(2).replace(".md", ".html")}">{m.group(1)}</a>', part)
        part = re.sub(r'(?<!href=")(https?://[^\s<)]+[^\s<).,;:])', r'<a href="\1">\1</a>', part)
        part = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", part)
        out.append(part)
    return "".join(out)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", re.sub(r"`|\*", "", text.lower())).strip("-")


def cells(line: str) -> list[str]:
    # A pipe inside a code span belongs to the code, not to the table.
    parts, depth, cur = [], False, ""
    for ch in line.strip().strip("|"):
        if ch == "`":
            depth = not depth
        if ch == "|" and not depth:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return parts + [cur.strip()]


def convert(md: str) -> tuple[str, str]:
    """Markdown subset to HTML: headings, paragraphs, fenced code, tables, flat lists. Returns (title, body)."""
    lines, out, title, i = md.splitlines(), [], "", 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
        elif line.startswith("```"):
            code = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1
            rows = "".join(f'<div class="g-code__line"><span class="g-code__n">{n}</span><span></span><span>{html.escape(c) or " "}</span></div>' for n, c in enumerate(code, 1))
            out.append(f'<div class="g-code t-mono" role="region" aria-label="Code" tabindex="0">{rows}</div>')
        elif m := re.match(r"(#{1,4}) (.*)", line):
            level, text = len(m.group(1)), m.group(2)
            cls = {1: "t-lg", 2: "t-md", 3: "t-sm", 4: "t-body-strong"}[level]
            if level == 1:
                title = re.sub(r"`", "", text)
            out.append(f'<h{level} class="{cls}" id="{slug(text)}">{inline(text)}</h{level}>')
            i += 1
        elif line.startswith("|"):
            block = []
            while i < len(lines) and lines[i].startswith("|"):
                block.append(cells(lines[i]))
                i += 1
            head, rows = block[0], [r for r in block[1:] if not all(set(c) <= set("-: ") for c in r)]
            th = "".join(f"<th>{inline(c)}</th>" for c in head)
            body = "".join("<tr>" + "".join(
                f'<td>{"" if n == 0 else f"<span class=\"d-label t-tag\">{inline(head[n])}</span>"}{inline(c)}</td>'
                for n, c in enumerate(r)) + "</tr>" for r in rows)
            wide = " d-wide" if len(head) >= 5 else ""
            out.append(f'<div class="g-table-wrap"><table class="g-table g-table--stack{wide} t-small"><thead class="t-tag"><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>')
        elif re.match(r"(- |\d+\. )", line):
            tag = "ol" if line[0].isdigit() else "ul"
            items = []
            while i < len(lines) and (re.match(r"(- |\d+\. )", lines[i]) or (lines[i].startswith("   ") and items)):
                if re.match(r"(- |\d+\. )", lines[i]):
                    items.append(re.sub(r"^(- |\d+\. )", "", lines[i]))
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            out.append(f'<{tag} class="t-body">' + "".join(f"<li>{inline(t)}</li>" for t in items) + f"</{tag}>")
        else:
            para = []
            while i < len(lines) and lines[i].strip() and not re.match(r"(```|#{1,4} |\||- |\d+\. )", lines[i]):
                para.append(lines[i].strip())
                i += 1
            out.append(f'<p class="t-body">{inline(" ".join(para))}</p>')
    return title, "\n".join(out)


def nav(current: str) -> str:
    items, group = [], ""
    for name, label, g in PAGES:
        if g != group:
            items.append(f'<span class="g-nav__group t-tag g-caps">{g}</span>')
            group = g
        here = ' aria-current="page"' if name == current else ""
        items.append(f'<a class="g-nav__item t-body" href="{name}.html"{here}>{label}</a>')
    return "\n".join(items)


def page(name: str, label: str, body: str) -> str:
    n = [p[0] for p in PAGES].index(name)
    prev = f'<a class="g-btn g-btn--quiet t-body" href="{PAGES[n - 1][0]}.html">{icon("left")}{PAGES[n - 1][1]}</a>' if n else "<span></span>"
    nxt = f'<a class="g-btn g-btn--quiet t-body" href="{PAGES[n + 1][0]}.html">{PAGES[n + 1][1]}{icon("right")}</a>' if n + 1 < len(PAGES) else ""
    menu_links = "".join(f'<a class="g-menu__item t-body" href="{p}.html"{" aria-current=\"page\"" if p == name else ""} style="text-decoration: none">{l}</a>' for p, l, _ in PAGES)
    return f"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{label}: Gantry docs</title>
<link rel="stylesheet" href="gantry.css">
{THEME_SCRIPT}
</head>
<body>
<div class="g-shell">
<nav class="g-nav g-nav--side" aria-label="Docs">
<a class="g-nav__brand" href="index.html"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Gantry docs</span></a>
{nav(name)}
<div class="g-nav__foot"><a class="t-small" href="../site/index.html">Gantry website</a><span class="t-mono-sm g-muted">version 0.0.1</span><button class="g-btn g-btn--quiet g-btn--sm t-small d-theme" type="button">Switch theme</button></div>
<a class="g-nav__menu g-btn g-btn--quiet g-btn--sm t-small" href="#menu">{icon("menu")}Menu</a>
</nav>
<main class="g-shell__main">
<article class="d-doc">
{body}
<nav class="d-pager" aria-label="Next and previous">{prev}{nxt}</nav>
</article>
</main>
</div>
<div class="g-scrim g-menu-sheet" id="menu">
<nav class="g-sheet" aria-label="Menu">
<div class="g-pager"><span class="t-md">Docs</span><a class="g-btn g-btn--quiet g-btn--icon" href="#" aria-label="Close the menu">{icon("close")}</a></div>
<div class="g-stack" style="gap: var(--space-1)">{menu_links}</div>
<div class="g-stack" style="gap: var(--space-2)"><a class="t-small" href="../site/index.html">Gantry website</a><button class="g-btn g-btn--quiet g-btn--sm t-small d-theme" type="button">Switch theme</button></div>
</nav>
</div>
{TOGGLE_SCRIPT}
</body>
</html>
"""


def image_size() -> str:
    """The image size `scripts/release.sh image` measured for this build, or where to get it."""
    measured = ROOT / "dist" / "image-size.txt"
    return measured.read_text().splitlines()[0] if measured.exists() else "small (run scripts/release.sh image for its size)"


def main() -> None:
    for need in (TOKENS, DESIGN / "components" / "bundle.css", DESIGN / "fonts"):
        if not need.exists():
            raise SystemExit(f"{need} is missing. Pass the design system folder: python3 scripts/docs.py <path to design-system/project>.")
    shutil.rmtree(OUT, ignore_errors=True)
    (OUT / "fonts").mkdir(parents=True)
    for font in (DESIGN / "fonts").glob("*.woff2"):
        shutil.copy(font, OUT / "fonts" / font.name)
    (OUT / "gantry.css").write_text(TOKENS.read_text() + (DESIGN / "components" / "bundle.css").read_text() + DOCS_CSS)
    for name, label, _ in PAGES:
        source = DOCS / f"{name}.md"
        title, body = convert(source.read_text().replace("{{IMAGE_SIZE}}", image_size()))
        text = page(name, title or label, body)
        # The house style has no long dashes. A page that has one is a mistake in its Markdown.
        for dash in (chr(0x2013), chr(0x2014)):
            if dash in text:
                raise SystemExit(f"{source} contains a long dash. Use a hyphen, a comma, a colon or parentheses.")
        for link in re.findall(r'href="([a-z-]+)\.html', text):
            if link not in {p[0] for p in PAGES}:
                raise SystemExit(f"{source} links to {link}.html, which is not a docs page.")
        (OUT / f"{name}.html").write_text(text)
    print(f"{len(PAGES)} pages written to {OUT}")


def demo() -> None:
    """The converter's one check: every construct the docs use comes out as expected."""
    _, body = convert("# T `x`\n\nA **b** [c](d.md) https://e.com/f.\n\n- one\n   two\n- `a|b`\n\n| h | i |\n|---|---|\n| `p|q` | r |\n\n```\n<x>\n```\n")
    assert '<h1 class="t-lg" id="t-x">T <code>x</code></h1>' in body, body
    assert '<strong>b</strong> <a href="d.html">c</a> <a href="https://e.com/f">https://e.com/f</a>.' in body, body
    assert "<li>one two</li>" in body and "<code>a|b</code>" in body, body
    assert "<td><code>p|q</code></td>" in body and "&lt;x&gt;" in body, body


if __name__ == "__main__":
    demo()
    main()
