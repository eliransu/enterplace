#!/usr/bin/env python3
"""Builds the Gantry website: src/ in, public/ out. Standard library only.

    python3 build.py           build public/
    python3 build.py --check   build, then fail if any internal link has no page

A page is src/pages/<path>.html. It starts with a comment of `key: value` lines
(title, description, nav) and the rest is the content of <main>. It is written to
public/<path>/index.html, so /use-cases/coding-agents/ is a clean URL.
"""
import hashlib
import html
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent
SRC, OUT = ROOT / "src", ROOT / "public"
SITE = "https://gantry.enterplace.dev"
DOCS = "https://gantry-docs.enterplace.dev"
VERSION = "0.1.0"
ROOT_FILES = {"404"}  # written as public/<name>.html, left out of the sitemap


def partial(name):
    return (SRC / "partials" / f"{name}.html").read_text()


def gate(block):
    """{{gate ... }}: the request motif. Lines are `lane: caller | tool | provider`,
    `req: lane | who | team | verdict | detail | stop label`, `label:` and `foot:`.
    The page gets the end state (so it reads without script); site.js replays the requests."""
    lanes, reqs, opt = [], [], {}
    for line in block.strip().splitlines():
        key, _, value = line.strip().partition(": ")
        cells = [c.strip() for c in value.split(" | ")]
        if key == "lane":
            lanes.append(cells)
        elif key == "req":
            reqs.append([int(cells[0])] + cells[1:])
        else:
            opt[key] = value
    out = [f'<figure class="gate" data-gate aria-label="{html.escape(opt["label"], quote=True)}">', '<div class="gate-lanes" aria-hidden="true">']
    for i, (who, tool, to) in enumerate(lanes):
        last = [r for r in reqs if r[0] == i][-1]
        stopped = last[3] in ("refused", "blocked")
        disc = f'<span class="runner {"stopped" if stopped else "passed"}"><span class="disc"></span></span>'
        stop = f'<span class="lane-stop on">{last[5]}</span>' if stopped else ""
        out.append(f'<div class="lane"><span class="lane-from">{who}<i>{tool}</i></span><span class="lane-track">{disc}{stop}</span><span class="lane-to">{to}</span></div>')
    out.append('</div>\n<ol class="records" aria-label="Example audit records, newest first">')
    rows, prev, n = [], "000000", 37
    for r in reqs[-4:]:
        n += 1
        digest = hashlib.sha256((prev + "|".join(map(str, r))).encode()).hexdigest()[:6]
        rows.append(f'<li><span>#{n}</span><span class="r-who">{r[1]}<i>{r[2]}</i></span><span class="v v-{r[3]}">{r[3]}</span><span class="r-meta">{r[4]}</span><span class="r-hash">{prev} &larr; {digest}</span></li>')
        prev = digest
    out += reversed(rows)
    out.append(f'</ol>\n<figcaption class="gate-foot"><span>{opt["foot"]}</span><button class="gate-pause" type="button" aria-pressed="false">Pause</button></figcaption>')
    out.append(f'<script type="application/json">{json.dumps({"n": n, "last": prev, "seq": reqs})}</script>\n</figure>')
    return "\n".join(out)


def expand(text):
    """{{> name}} pulls in a partial. docs:/path is short for a page of the docs site."""
    text = re.sub(r"\{\{> ([\w-]+)\}\}", lambda m: expand(partial(m.group(1))), text)
    text = re.sub(r"\{\{gate\n(.*?)\n\}\}", lambda m: gate(m.group(1)), text, flags=re.S)
    text = text.replace('href="docs:', f'href="{DOCS}')
    return text.replace("{{version}}", VERSION)


def read_page(path):
    raw = path.read_text()
    m = re.match(r"<!--\n(.*?)\n-->\n", raw, re.S)
    if not m:
        sys.exit(f"{path}: the page must start with a <!-- title: ... --> comment")
    meta = dict(line.split(": ", 1) for line in m.group(1).splitlines())
    for key in ("title", "description"):
        if key not in meta:
            sys.exit(f"{path}: missing `{key}`")
    return meta, raw[m.end():]


def build():
    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(SRC / "static", OUT)
    layout = partial("layout")
    urls = []
    for path in sorted((SRC / "pages").rglob("*.html")):
        meta, body = read_page(path)
        rel = path.relative_to(SRC / "pages").with_suffix("")
        if rel.as_posix() in ROOT_FILES:
            url, dest = f"/{rel}.html", OUT / f"{rel}.html"
        elif rel.name == "index":
            url = "/" + (rel.parent.as_posix() + "/" if rel.parent.as_posix() != "." else "")
            dest = OUT / rel.parent / "index.html"
        else:
            url, dest = f"/{rel.as_posix()}/", OUT / rel / "index.html"
        page = layout.replace("{{content}}", body)
        page = expand(page)
        for key in ("title", "description"):
            page = page.replace("{{" + key + "}}", html.escape(meta[key], quote=True))
        page = page.replace("{{url}}", SITE + url)
        page = page.replace("{{body_class}}", meta.get("class", ""))
        # Mark where the reader is: the link to this page, and its group in the header.
        page = page.replace(f'href="{url}"', f'href="{url}" aria-current="page"')
        if "nav" in meta:
            page = page.replace(f'data-group="{meta["nav"]}"', f'data-group="{meta["nav"]}" data-here')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(page)
        if rel.as_posix() not in ROOT_FILES:
            urls.append(url)
    locs = "".join(f"<url><loc>{SITE}{u}</loc></url>" for u in sorted(urls))
    (OUT / "sitemap.xml").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{locs}</urlset>\n'
    )
    return urls


def check():
    """Every href and src that starts with / must be a file in public/. Every #id must exist on its page."""
    bad = []
    for page in OUT.rglob("*.html"):
        text = page.read_text()
        ids = set(re.findall(r'\bid="([^"]+)"', text))
        for link in set(re.findall(r'(?:href|src|srcset)="(/[^"]*|#[^"]+)"', text)):
            target, _, frag = link.partition("#")
            if not target:
                if frag not in ids:
                    bad.append(f"{page.relative_to(OUT)}: #{frag} is not on the page")
                continue
            f = OUT / target.lstrip("/")
            f = f / "index.html" if target.endswith("/") else f
            if not f.is_file():
                bad.append(f"{page.relative_to(OUT)}: {link} has no file")
            elif frag and f'id="{frag}"' not in f.read_text():
                bad.append(f"{page.relative_to(OUT)}: {link} has no such id")
        if chr(0x2013) in text or chr(0x2014) in text:
            bad.append(f"{page.relative_to(OUT)}: holds an en or em dash")
    if bad:
        sys.exit("\n".join(sorted(bad)))


if __name__ == "__main__":
    pages = build()
    if "--check" in sys.argv:
        check()
    print(f"Built {len(pages)} pages and 404.html into {OUT}")
