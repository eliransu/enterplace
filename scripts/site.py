"""Builds the Gantry website into site/public/ from the approved landing page design.

The design lives outside this repository, so the built page is committed and CI deploys it as it is.
Rebuild it here after a design change.

Usage: python3 scripts/site.py [design-screens folder]
The markup comes from the design's own helpers in design-screens/build.py (tags, buttons, the motif, points,
commands, the policy block), so the page stays the approved design. The copy is changed where the design shows
what is not built yet: no price, more than one node marked next, and an install section that works today.
"""
import importlib.util, pathlib, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "public"
# The repository sits beside design-screens, or one level deeper in a working copy.
SCREENS = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else next((p / "design-screens" for p in (ROOT.parent, ROOT.parent.parent) if (p / "design-screens").is_dir()), ROOT.parent / "design-screens")
SYSTEM = SCREENS.parent / "design-system" / "project"

spec = importlib.util.spec_from_file_location("design", SCREENS / "build.py")
if spec is None or spec.loader is None:
    raise SystemExit(f"{SCREENS / 'build.py'} is missing. Pass the design-screens folder: python3 scripts/site.py <path>.")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

DOCS = "https://gantry-docs.eliran.me"
# `scripts/release.sh image` writes the measured size ("8.2 MB" then the bytes) for the release to fill in.
_measured = (ROOT / "dist" / "image-size.txt").read_text().split() if (ROOT / "dist" / "image-size.txt").exists() else []
IMAGE_SIZE = " ".join(_measured[:2]) if len(_measured) >= 3 else "small"
IMAGE_BYTES = _measured[2] if len(_measured) >= 3 else "(measured at release)"

# Five records as the audit log holds them today: allowed, refused by policy, or refused by a guardrail.
RECORDS = [  # time, verdict, who, team
    ("14:02:11", ("refused", "Refused", "model_not_allowed"), "dana.levi", "interns"),
    ("14:02:10", ("refused", "Refused", "unknown_key"), "unknown", "key 9f3a61c2"),
    ("14:02:09", ("block", "Block", "private_key"), "svc-invoice-bot", "payments"),
    ("14:02:08", ("allow", "Allow", ""), "maya.cohen", "payments"),
    ("14:02:07", ("allow", "Allow", ""), "noa.bar", "platform"),
]
REFUSED_ID = d.ulid("site-refused")


def split_table() -> str:
    """The design's table of what is open source and what is built, with the rows this version has built."""
    rows = [  # feature, open source, built today
        ("Keys per person and workload, a policy file, and a check for it", True, True),
        ("A hash-chained audit log: a changed, inserted or reordered record breaks the chain", True, True),
        ("Guardrails per rule on requests and answers: secrets, personal data, seven guardrail vendors, and outside services by webhook", True, True),
        ("Budgets, requests and tokens per minute and a cache per rule, with the cost of every answer and prices built in for most models; expiry, a budget, models and tokens per minute per key", True, True),
        ("Model aliases with load balancing, cooldown and fallbacks; a policy from a LiteLLM config", True, True),
        ("An admin console for the audit log, keys, policy and spend", True, True),
        ("Console sign-in with your identity provider (OpenID Connect), with admin and read-only roles", True, True),
        ("Prometheus metrics, and an audit log your log shipper can tail", True, True),
        ("Developer sign-in for their own key (gantry login)", True, True),
        ("Claude Code to any model: GPT, Gemini, local models, Claude on Bedrock and Vertex AI", True, True),
        ("Kill switches with a reason the people stopped see", True, True),
        ("More than one node", True, False),
        ("Coverage and enforcement across a fleet of laptops", False, False),
        ("Export to your SIEM, retention and legal hold", False, False),
        ("Policy dry run, versions and approvals", False, False),
        ("Cloud identity for workloads, SCIM", False, False),
    ]
    def where(free: bool, built: bool) -> str:
        if not free:
            return d.PRODUCT
        return d.tag("", "Open source") if built else d.tag("", "Open source", "next")
    body = "".join(f'<tr><td style="white-space: normal">{what}</td><td>{where(free, built)}</td></tr>' for what, free, built in rows)
    return ('<div class="g-table-wrap"><table class="g-table t-body"><thead class="t-tag"><tr><th>What you get</th><th>In</th></tr></thead>'
            f'<tbody>{body}</tbody></table></div><p class="t-small g-muted" style="margin: 0">Rows marked next are open source and arrive in the coming releases.</p>')


def records() -> str:
    # The design's third column, Time, sits under the name here: refusal codes are longer than the design's
    # guardrail names, and three columns no longer fit the panel.
    body = "".join(f'<tr><td>{who}<span class="g-table__sub">{team}, {time}</span></td><td>{d.tag(*verdict)}</td></tr>' for time, verdict, who, team in RECORDS)
    return ('<div class="g-table-wrap"><table class="g-table g-table--stack t-mono-sm"><thead class="t-tag"><tr><th>Person or workload</th><th>Verdict</th></tr></thead>'
            f"<tbody>{body}</tbody></table></div>")


# The policy the site shows, and what `gantry check` prints for it. scripts/check_examples.py runs it through
# `gantry check` and compares the output, so the site never shows a policy that does not load.
POLICY = """\
# Who may use which model.
version: 1
providers:
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-5-5, claude-haiku-5-5]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [claude-sonnet-5-5, claude-haiku-5-5]
  - name: everyone-else
    principals: { any: true }
    models: []
"""
CHECKED = "gantry.policy.yaml is valid: 2 rules, 0 keys, 1 provider: anthropic (anthropic) at https://api.anthropic.com."
# The line the panel marks: the rule that refuses everyone the rules above it do not name.
REFUSING = next(n for n, line in enumerate(POLICY.splitlines(), 1) if "everyone-else" in line)


def policy() -> list[tuple]:
    def styled(line: str) -> str:
        if line.startswith("#"):
            return f'<span class="g-code__c">{line}</span>'
        key, _, value = line.partition(": ")
        if not value:
            return line
        indent = len(key) - len(key.lstrip())
        return d.kv(key.strip(), value, indent)
    return [(n, "", styled(text), "hit" if n == REFUSING else "") for n, text in enumerate(POLICY.splitlines(), 1)]


LANDING = f"""<div style="background: var(--ground); color: var(--text); overflow-wrap: anywhere">

<section class="g-frame" data-theme="dark">
<nav class="g-nav" aria-label="Website">
<a class="g-nav__brand" href="#top"><span class="g-mark" aria-hidden="true"></span><span class="t-sm">Gantry</span></a>
<a class="g-nav__item t-body" href="#policy">Product</a>
<a class="g-nav__item t-body" href="#coverage">Coverage</a>
<a class="g-nav__item t-body" href="{DOCS}/">Docs</a>
{d.btn("Quickstart", small=True, href="#start")}
</nav>
<div class="g-hero">
<div class="g-stack" style="gap: var(--space-6)">
<h1 class="t-hero g-caps" id="top" style="margin: 0; text-wrap: balance">Every AI request on the record</h1>
<p class="t-lead g-muted g-measure" style="margin: 0">An open source AI gateway for companies rolling out Claude Code and their own agents. It puts a person, a policy decision and an audit record on every request, before the request leaves.</p>
<div class="g-head__actions">{d.command("gantry serve gantry.policy.yaml")}{d.btn("See a policy file", "quiet", href="#policy")}</div>
</div>
<div class="g-stack" style="gap: var(--space-6); justify-items: start">
{d.motif(["", "", "", "", "", "", "", "flame", "", "", "", ""], ["lime", "lime", "lime", "lime", "lime", "gap", "lime", "lime", "lime"], 4, 3)}
<div class="g-panel g-stack" style="gap: var(--space-2); justify-items: start">{d.tag("refused", "Refused", "model_not_allowed")}<span class="t-mono-sm">14:02:11 dana.levi, claude-sonnet-5-5</span><span class="t-mono-sm g-muted">decision {REFUSED_ID}</span><span class="t-small g-muted">A request that was refused, and the record that proves it.</span></div>
</div>
</div>
</section>

<section class="g-section">
<div class="g-split">
<div class="g-stack g-split__wide" style="gap: var(--space-6)">
<h2 class="t-xl" style="margin: 0; text-wrap: balance">What a team needs to run it safely is free</h2>
<p class="t-lead g-muted g-measure" style="margin: 0">Under Apache 2.0, for any number of people. The product is what a company adds to prove and operate it across everyone.</p>
{split_table()}
</div>
<div class="g-panel g-stack">
{records()}
<p class="t-small g-muted" style="margin: 0">Five records from an audit log. Three were refused, and each says why: a model the rule does not allow, a key Gantry never issued, and a request a guardrail stopped before it left. Read them in the console at <span class="t-mono">/console</span>, or check the chain with <span class="t-mono">gantry audit verify</span>.</p>
</div>
</div>
</section>

<section class="g-section" id="policy">
<header class="g-head">
<h2 class="g-head__title t-xl">One file. Every rule.</h2>
<p class="g-head__lead t-lead">Which providers, which models, and who may use them. One file your team reviews like code, and <span class="t-mono">gantry check</span> names every mistake with its line.</p>
</header>
<div class="g-split">
<div class="g-panel g-stack g-split__wide">
<div class="g-pager"><span class="t-mono-lg">gantry.policy.yaml</span>{d.tag("refused", "Refused", f"line {REFUSING}")}</div>
{d.code(policy())}
<p class="t-small g-muted" style="margin: 0">Rules are read in order and the first that names the caller decides. A rule can also name guardrails, and set a budget in dollars, a rate limit and a cache.</p>
</div>
{d.points([("Line 4, where", "A provider, the API it speaks and the exact models it serves. Its key stays in an environment variable."),
           ("Line 11, who", "A team, a person or a workload, or anyone. No anonymous requests."),
           ("Line 12, what", "The models this team may reach. Anything else is refused with a reason."),
           ("Line 13, everyone else", "This rule refused the request above. The record names the rule and its line.")])}
</div>
</section>

<section class="g-section g-sheet-dark" id="coverage" data-theme="dark">
<header class="g-head">
<h2 class="g-head__title t-xl">Laptops and workloads. One gate.</h2>
<p class="g-head__lead t-lead">A coding agent on a laptop and a job in a cluster pass the same gate, under the same policy, into the same audit log.</p>
</header>
<div class="g-panel g-flow" style="padding: var(--space-16) var(--space-6)">
<div class="g-flow__row">{"".join(d.tag("", t) for t in ["Claude Code", "Codex", "OpenAI clients", "Your agents"])}</div>
<span class="g-flow__link" aria-hidden="true"></span>
<span class="g-flow__gate t-md">Identify, check, record</span>
<span class="g-flow__link" aria-hidden="true"></span>
<div class="g-flow__row">{"".join(d.tag("", t) for t in ["Anthropic", "OpenAI", "Azure OpenAI", "Amazon Bedrock", "Gemini", "Vertex AI", "Groq", "Ollama", "vLLM"])}</div>
</div>
<div class="g-split">
<div class="g-stack">
<h3 class="t-md" style="margin: 0">On one machine, free</h3>
{d.points([("gantry key new", "An admin makes a key for a person or a workload. Every request from their tools then carries their name. Admins sign in to the console with an admin key or through your identity provider.")], ident=True)}
{d.points([("Yours to host", "Prompts, answers and provider keys stay in your environment. The audit log holds no prompt text.")])}
</div>
<div class="g-stack">
<div class="g-toolbar"><h3 class="t-md" style="margin: 0">Across the fleet</h3>{d.PRODUCT}</div>
{d.points([("Coverage you can prove", "Each tool on each laptop is configured, verified or enforced, and the report says which."),
           ("Workloads without static keys", "A job proves who it is with its cloud identity.")])}
<p class="t-small g-muted" style="margin: 0">The product is in development. Nothing here is for sale yet.</p>
</div>
</div>
</section>

<section class="g-section" id="start">
<header class="g-head">
<h2 class="g-head__title t-xl">Check the file, make a key, serve</h2>
<p class="g-head__lead t-lead">One binary and no database. Build it from source, or build the container image: one static binary, {IMAGE_SIZE}, not root.</p>
</header>
<div class="g-split">
<div class="g-stack g-split__wide">
<div class="g-terminal t-mono"><span>$ cargo build --release</span><span>$ gantry check gantry.policy.yaml</span><span class="g-terminal__out">{CHECKED}</span><span>$ gantry key new maya.cohen --team payments</span><span class="g-terminal__out">Key for maya.cohen, team payments. It is shown once and is not stored anywhere.</span><span>$ export ANTHROPIC_PROVIDER_KEY=...</span><span>$ gantry serve gantry.policy.yaml</span><span class="g-terminal__out">gantry 0.0.1 listening on http://127.0.0.1:8080</span></div>
<div class="g-terminal t-mono"><span>$ scripts/release.sh image</span><span class="g-terminal__out">gantry:0.0.1: {IMAGE_BYTES} bytes, user 65532:65532</span><span>$ docker run --rm -p 127.0.0.1:8080:8080 -v "$PWD/gantry.policy.yaml:/etc/gantry/gantry.policy.yaml:ro" -v "$PWD/keys:/etc/gantry/keys" -v gantry-audit:/var/lib/gantry -e ANTHROPIC_PROVIDER_KEY gantry:local serve /etc/gantry/gantry.policy.yaml --keys /etc/gantry/keys/gantry.keys.yaml --listen 0.0.0.0:8080</span></div>
</div>
<div class="g-stack">
<h3 class="t-md" style="margin: 0">What each one does</h3>
{d.points([("gantry check", "Names the file, the line and the word for every mistake, before anything runs."),
           ("gantry key new", "Prints a key once. Gantry keeps only its hash."),
           ("gantry serve", "Identifies, checks and records every request, then forwards it with the provider's key."),
           ("gantry audit verify", "Proves the log is one unbroken chain, and prints the last hash to keep elsewhere.")], ident=True)}
<div class="g-head__actions">{d.btn("Read the quickstart", href=DOCS + "/getting-started/quickstart/")}{d.btn("Point Claude Code at it", "quiet", href=DOCS + "/integrations/claude-code/")}</div>
</div>
</div>
</section>

<div style="padding: 0 var(--space-4) var(--space-4)">
<section class="g-section" style="border-radius: var(--radius-xl); background: var(--lime); color: var(--on-lime)" data-theme="light">
<h2 class="t-hero g-caps" style="margin: 0; max-width: var(--measure-wide); text-wrap: balance">Put a gate in front of your AI</h2>
<div class="g-head__actions">{d.command("gantry serve gantry.policy.yaml")}</div>
</section>
</div>

<footer class="g-footer" data-theme="dark">
<div class="g-stack g-measure" style="justify-items: start">
<span class="g-mark" aria-hidden="true"></span>
<p class="t-sm" style="margin: 0">Every AI request identified, checked and recorded.</p>
<p class="t-small g-muted" style="margin: 0">Open source under Apache 2.0. Version 0.0.1.</p>
</div>
<nav class="g-footer__links" aria-label="Footer">
<a class="t-lead" href="#policy">Product</a>
<a class="t-lead" href="#coverage">Coverage</a>
<a class="t-lead" href="#start">Quickstart</a>
<a class="t-lead" href="{DOCS}/">Docs</a>
<a class="t-lead" href="{DOCS}/operations/security/">Security</a>
<a class="t-lead" href="{DOCS}/migrate/comparison/">Compared with LiteLLM and Bifrost</a>
</nav>
</footer>

</div>"""

FONT_FACES = """
@font-face{font-family:"Familjen Grotesk";src:url("fonts/FamiljenGrotesk-Variable.woff2") format("woff2");font-weight:400 700;font-display:swap}
@font-face{font-family:"Fragment Mono";src:url("fonts/FragmentMono-Regular.woff2") format("woff2");font-weight:400;font-display:swap}
a{color:inherit}a:hover{color:inherit}
"""

# Only what the page needs on top of the components, and only with tokens. Between a phone and a wide screen the
# hero's motif steps its discs down, so its third column is not cut at the edge and the page does not scroll sideways.
SITE_CSS = """
@media (min-width:721px) and (max-width:1100px){.g-hero .g-motif{--g-disc:var(--space-6)}}
/* On a phone the footer is the site's menu: each of its links is a 44px touch target. */
@media (max-width:720px){.g-footer__links a{display:inline-flex;align-items:center;min-height:var(--control-md)}}
"""

# The page follows the system theme. ?theme= sets it for screenshots. Copy puts the command on the clipboard.
SCRIPTS = """<script>(function(){var t=new URLSearchParams(location.search).get('theme');
if(t!=='light'&&t!=='dark')t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.body.dataset.theme=t})();
document.querySelectorAll('.g-command').forEach(function(c){var b=c.querySelector('button');if(!b)return;b.addEventListener('click',function(){
var text=c.querySelector('.g-command__text').textContent;if(navigator.clipboard)navigator.clipboard.writeText(text)})})</script>"""


def main() -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    (OUT / "fonts").mkdir(parents=True)
    for font in (SYSTEM / "fonts").glob("*.woff2"):
        shutil.copy(font, OUT / "fonts" / font.name)
    tokens = (SCREENS / "project" / "ds" / "gantry" / "tokens.css").read_text()
    (OUT / "site.css").write_text(FONT_FACES + tokens + (SYSTEM / "components" / "bundle.css").read_text() + SITE_CSS)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gantry: every AI request on the record</title>
<meta name="description" content="An open source AI gateway that puts a person, a policy decision and an audit record on every request, before the request leaves.">
<link rel="stylesheet" href="site.css">
</head>
<body data-theme="light">
{LANDING}
{SCRIPTS}
</body>
</html>
"""
    for dash in (chr(0x2013), chr(0x2014)):
        if dash in page:
            raise SystemExit("The page contains a long dash. Use a hyphen, a comma, a colon or parentheses.")
    for word in ("$0", "Pricing", "aws_access_key", "per governed person"):
        if word in page:
            raise SystemExit(f'The page says "{word}", which is not true of this version. Change the copy.')
    (OUT / "index.html").write_text(page)
    print(f"{OUT / 'index.html'}")


if __name__ == "__main__":
    main()
