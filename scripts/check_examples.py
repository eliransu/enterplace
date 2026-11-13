"""Runs every policy example a reader can copy through `gantry check`, so no example can drift from the code.

Usage: python3 scripts/check_examples.py [path/to/gantry]
Checked: every fenced block in README.md and the docs site pages (docs/src/content/docs) with a top-level `version:` line (a whole policy file).
A fragment (a block whose top-level keys are all policy sections, such as `guardrails:` or `providers:` alone) is
pasted into a minimal policy, replacing that section, and checked the same way. A block written to show a mistake on
purpose, or holding placeholders, is skipped when the line just above its fence says `<!-- not checked -->`.
Standard library only.
"""
import pathlib, re, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GANTRY = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "release" / "gantry"


# The minimal policy a fragment is pasted into. A section the fragment has replaces the one here.
SECTIONS = ["providers", "rules", "guardrails", "prices", "audit", "console", "store"]
MINIMAL = {
    "providers": "providers:\n  - name: openai\n    kind: openai\n    url: https://api.openai.com/v1\n"
    "    key_env: OPENAI_API_KEY\n    models: [gpt-4o-mini]\n",
    "rules": 'rules:\n  - name: everyone\n    principals: { any: true }\n    models: ["*"]\n',
}


def whole(body: list):
    """The block as a whole policy: itself if it is one, a minimal policy around it if it is a fragment, else None."""
    if any(re.match(r"version:\s*1\b", line) for line in body):
        return "\n".join(body) + "\n"
    parts, current = {}, None
    for line in body:
        top = re.match(r"(\w+):", line)
        if top:
            current = top.group(1)
            if current not in SECTIONS:
                return None
            parts[current] = ""
        elif current is None and line.strip() and not line.lstrip().startswith("#"):
            return None
        if current:
            parts[current] += line + "\n"
    if not parts:
        return None
    sections = {**MINIMAL, **parts}
    return "version: 1\n" + "".join(sections[name] for name in SECTIONS if name in sections)


def blocks(path: pathlib.Path):
    """(line, text) of each fenced block in a Markdown file that holds a policy or a policy fragment."""
    lines = path.read_text().splitlines()
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith("```"):
            start, body = i, []
            i += 1
            while i < len(lines) and not lines[i].lstrip().startswith("```"):
                body.append(lines[i])
                i += 1
            skipped = start > 0 and "not checked" in lines[start - 1]
            text = None if skipped else whole(body)
            if text:
                yield start + 1, text
        i += 1


def check(text: str, where: str, failures: list) -> str:
    with tempfile.TemporaryDirectory() as folder:
        policy = pathlib.Path(folder) / "gantry.policy.yaml"
        policy.write_text(text)
        run = subprocess.run([str(GANTRY), "check", str(policy)], capture_output=True, text=True)
    if run.returncode != 0:
        failures.append(f"{where}: gantry check exits {run.returncode}:\n{run.stderr.replace(str(policy), 'gantry.policy.yaml')}")
    return run.stdout.replace(str(policy), "gantry.policy.yaml").strip()


def main() -> int:
    if not GANTRY.exists():
        print(f"{GANTRY} does not exist. Run `cargo build --release` first, or pass the binary.", file=sys.stderr)
        return 2
    failures, count = [], 0
    for path in [ROOT / "README.md", *sorted((ROOT / "docs" / "src" / "content" / "docs").rglob("*.md*"))]:
        for line, text in blocks(path):
            count += 1
            check(text, f"{path.relative_to(ROOT)}:{line}", failures)
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{count} policy examples checked, {len(failures)} failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
