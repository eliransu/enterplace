#!/usr/bin/env python3
"""Turns Gitleaks' default rule set (config/gitleaks.toml, MIT license) into the JSON the `secrets` guardrail's
`pack: gitleaks` reads: crates/gantry-core/data/gitleaks-rules.json.

Usage: scripts/gitleaks_import.py <gitleaks.toml> <gitleaks commit sha>

Kept: each rule's id, regex, secretGroup, entropy and keywords, its allowlists' regexes and stopwords, and the
global allowlist's regexes and stopwords. Dropped: path rules (a prompt has no file path) and rules that match on a
path only. Python's tomllib reads the file; nothing else is needed.
"""

import json
import re
import sys
import tomllib

REPEAT = re.compile(r"\{\d+(?:,\d*)?\}")


def rust(pattern):
    """Go's RE2 reads a brace that starts no repetition as a literal brace; Rust's regex refuses it. Escaped here,
    the one change made to any rule."""
    out, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if in_class:
            in_class = c != "]" or (out and out[-1] == "[")
        elif c == "[":
            in_class = True
        elif c == "{":
            m = REPEAT.match(pattern, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
            c = "\\{"
        elif c == "}":
            c = "\\}"
        out.append(c)
        i += 1
    return "".join(out)


def allowlists(lists):
    out = []
    for a in lists:
        if a.get("paths") and not (a.get("regexes") or a.get("stopwords")):
            continue
        out.append(
            {
                "regexes": [rust(r) for r in a.get("regexes", [])],
                "stopwords": [s.lower() for s in a.get("stopwords", [])],
                "target": a.get("regexTarget", "secret"),
                # AND with a path condition can never hold on a prompt: such a list allows nothing.
                "and_path": a.get("condition") == "AND" and bool(a.get("paths")),
            }
        )
    return out


def main():
    source, sha = sys.argv[1], sys.argv[2]
    with open(source, "rb") as f:
        config = tomllib.load(f)
    rules = []
    for r in config["rules"]:
        if "regex" not in r:
            continue
        rules.append(
            {
                "id": r["id"],
                "regex": rust(r["regex"]),
                "secret_group": r.get("secretGroup", 0),
                "entropy": r.get("entropy"),
                "keywords": [k.lower() for k in r.get("keywords", [])],
                "allowlists": allowlists(r.get("allowlists", [])),
            }
        )
    glob = config.get("allowlist", {})
    out = {
        "source": "https://github.com/gitleaks/gitleaks/blob/%s/config/gitleaks.toml" % sha,
        "license": "MIT, Copyright (c) 2019 Zachary Rice. Rules imported with literal braces escaped for Rust's regex; see crates/gantry-core/data/GITLEAKS-LICENSE.",
        "global": {
            "regexes": [rust(r) for r in glob.get("regexes", [])],
            "stopwords": [s.lower() for s in glob.get("stopwords", [])],
        },
        "rules": rules,
    }
    json.dump(out, sys.stdout, indent=1, ensure_ascii=True)
    sys.stdout.write("\n")


main()
