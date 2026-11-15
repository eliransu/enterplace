"""Drives the console's editing pages in a real headless Chrome against Postgres, and saves a screenshot of each.

Usage: python3 scripts/console_edit_check.py --database postgres://... [--fresh] [--gantry target/debug/gantry] [--out DIR]

The policy is kept in the store (`policy_from: store`, `approval: true`). The script issues an admin key and a
second admin, serves Gantry, signs in through the browser form, adds a model, edits a key, saves a version for
approval, approves it as the second admin, runs a dry run, and screenshots Models, Teams, the key editor, the
editor with a dry run, Policy and Policy versions at 1440 wide (and Models at 390). The database must be empty or
one this script made: it imports its policy as version 1. With --fresh it makes its own: psql drops and creates the
database gantry_console_edit on the server --database names, and the check runs there. Uses browser_check.py's Chrome driver, the standard
library only. Exits 1 on the first check that fails.
"""
import argparse, json, os, pathlib, re, subprocess, sys, tempfile, time, urllib.parse, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from browser_check import CHROME, ROOT, Chrome, check, stop  # noqa: E402


def key_new(gantry: str, folder: pathlib.Path, env: dict, name: str) -> str:
    out = subprocess.run([gantry, "key", "new", name, "--team", "platform", "--admin", "--quiet",
                          "--policy", str(folder / "gantry.policy.yaml")],
                         cwd=folder, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"gantry key new failed: {out.stderr}")
    out = out.stdout
    found = re.search(r"gantry_[0-9a-zA-Z_]+", out)
    if not found:
        raise SystemExit(f"gantry key new printed no key: {out}")
    return found.group(0)


def fresh(url: str) -> str:
    """Drops and creates gantry_console_edit on the server `url` names, with psql, and returns its URL."""
    parts = urllib.parse.urlsplit(url)
    for sql in ("DROP DATABASE IF EXISTS gantry_console_edit", "CREATE DATABASE gantry_console_edit"):
        out = subprocess.run(["psql", url, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], capture_output=True, text=True)
        if out.returncode != 0:
            raise SystemExit(f"psql could not run {sql}: {out.stderr.strip()}. Check --database and that psql is installed.")
    return urllib.parse.urlunsplit(parts._replace(path="/gantry_console_edit"))


def api(base: str, key: str, method: str, path: str, body: str = "", headers: dict | None = None):
    request = urllib.request.Request(f"{base}{path}", data=body.encode() if body else None, method=method,
                                     headers={"authorization": f"Bearer {key}", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status, answer.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--database", required=True)
    parser.add_argument("--fresh", action="store_true", help="run in a new database gantry_console_edit (needs psql)")
    parser.add_argument("--gantry", default=str(ROOT / "target" / "debug" / "gantry"))
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--port", type=int, default=20660)
    parser.add_argument("--out", default=str(ROOT / "target" / "console-edit-screens"))
    args = parser.parse_args()
    server = args.database if args.fresh else None
    if args.fresh:
        args.database = fresh(args.database)
    gantry = str(pathlib.Path(args.gantry).resolve())
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    folder = pathlib.Path(tempfile.mkdtemp(prefix="gantry-edit-"))
    base = f"http://127.0.0.1:{args.port}"
    (folder / "gantry.policy.yaml").write_text(f"""version: 1
store: {{ postgres_url_env: GANTRY_DATABASE_URL, policy_from: store, approval: true }}
providers:
  - name: local
    kind: openai
    url: http://127.0.0.1:{args.port + 9}
    allow_private: true
    models: [local-model, local-large]
rules:
  - name: payments
    principals: {{ team: payments }}
    models: [local-model, local-large]
    budget: {{ usd: 200, per: month }}
  - name: everyone
    principals: {{ any: true }}
    models: [local-model]
prices:
  local-model: {{ input: 0.2, output: 0.8 }}
  local-large: {{ input: 2.5, output: 10 }}
audit: {{ path: gantry-audit.jsonl }}
""")
    env = {**os.environ, "GANTRY_DATABASE_URL": args.database}
    admin = key_new(gantry, folder, env, "ops.admin")
    second = key_new(gantry, folder, env, "noa.bar")
    subprocess.run([gantry, "key", "new", "maya.cohen", "--team", "payments", "--quiet", "--policy",
                    str(folder / "gantry.policy.yaml")], cwd=folder, env=env, capture_output=True, check=True)
    proc = subprocess.Popen([gantry, "serve", str(folder / "gantry.policy.yaml"), "--listen", f"127.0.0.1:{args.port}"],
                            cwd=folder, env=env, stdout=open(folder / "gantry.log", "w"), stderr=subprocess.STDOUT)
    chrome = None
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{base}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        chrome = Chrome(args.chrome, str(folder / "chrome"))
        chrome.size(1440)
        chrome.go(f"{base}/console/sign-in")
        chrome.js("document.getElementById('key').focus()")
        chrome.type(admin)
        chrome.key("Enter")
        chrome.wait("location.pathname === '/console/start'", "Start here after sign-in")

        # Models: add one through the dialog. Approval is on, so it waits; the second admin approves it.
        chrome.go(f"{base}/console/models?add=1")
        chrome.js("""(() => { const f = document.querySelector('form[action="/console/models/add"]');
            f.model.value = 'local-fast'; f.input.value = '0.15'; f.output.value = '0.6'; f.aliases.value = 'fast';
            f.submit(); })()""")
        chrome.wait("location.pathname === '/console/policy/versions' && document.readyState === 'complete'", "the new version")
        check("waiting for approval" in chrome.js("document.body.textContent").lower(), "a model added with approval on waits for a second admin")
        status, body = api(base, second, "POST", "/admin/policy/versions/2/approve")
        check(status == 200, f"the second admin approves version 2 ({status} {body[:200]})")
        time.sleep(1.5)
        chrome.go(f"{base}/console/models")
        check("local-fast" in chrome.js("document.body.textContent"), "the approved model is listed")
        chrome.shot(out / "models.png")
        chrome.go(f"{base}/console/models?price=local-large")
        chrome.shot(out / "models-price-dialog.png", full=False)
        chrome.size(390, 844)
        chrome.go(f"{base}/console/models")
        chrome.shot(out / "models-phone.png")
        chrome.size(1440)

        chrome.go(f"{base}/console/teams")
        check("maya.cohen" in chrome.js("document.body.textContent"), "teams list the people")
        chrome.shot(out / "teams.png")

        chrome.go(f"{base}/console/people")
        chrome.js("document.querySelector('a[href^=\"/console/people/edit\"]').click()")
        chrome.wait("location.pathname === '/console/people/edit' && document.readyState === 'complete'", "the key editor")
        chrome.shot(out / "key-edit.png")

        # A draft that narrows everyone's models: saved for approval, then dry-run from the editor.
        chrome.go(f"{base}/console/policy/edit")
        chrome.js("""(() => { const t = document.getElementById('policy-text');
            t.value = t.value.replace('principals: { any: true }\\n    models: [local-model]', 'principals: { any: true }\\n    models: []');
            document.getElementById('policy-note').value = 'everyone else gets no model'; })()""")
        chrome.js("document.querySelector('button[formaction=\"/console/policy/dry-run\"]').click()")
        chrome.wait("document.body.innerText.includes('Dry run') && document.querySelector('.g-tag')", "the dry run")
        check("every gateway on the store" in chrome.js("document.body.textContent"),
              "the dry run replays every gateway's requests from the store")
        chrome.shot(out / "policy-edit-dry-run.png")
        chrome.js("document.querySelector('form[action=\"/console/policy/save\"]').submit()")
        chrome.wait("location.pathname === '/console/policy/versions' && document.readyState === 'complete'", "the saved draft")
        chrome.shot(out / "policy-version-pending.png")

        chrome.go(f"{base}/console/policy")
        chrome.shot(out / "policy.png")
        chrome.go(f"{base}/console/policy/versions?version=2")
        chrome.shot(out / "policy-versions.png")
        print(f"console edit check passed; screenshots in {out}")
    except AssertionError as failed:
        print(f"FAILED: {failed}\nGantry's output: {folder / 'gantry.log'}", file=sys.stderr)
        sys.exit(1)
    finally:
        if chrome:
            chrome.close()
        stop(proc)
        if server:
            # The database --fresh made goes with the run, so a test Postgres does not grow by one a run.
            subprocess.run(["psql", server, "-q", "-c", "DROP DATABASE IF EXISTS gantry_console_edit WITH (FORCE)"],
                           capture_output=True, text=True)


if __name__ == "__main__":
    main()
