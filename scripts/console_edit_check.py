"""Drives the console's editing pages in a real headless Chrome against Postgres, and saves a screenshot of each.

Usage: python3 scripts/console_edit_check.py --database postgres://... [--fresh] [--enterplace target/debug/enterplace] [--out DIR]

The policy is kept in the store (`policy_from: store`, `approval: true`). The script issues an admin key and a
second admin, serves Enterplace, signs in through the browser form, adds a model, edits a key, saves a version for
approval, approves it as the second admin, runs a dry run, and screenshots Models, Teams, the key editor, the
editor with a dry run, Policy and Policy versions at 1440 wide (and Models at 390). The database must be empty or
one this script made: it imports its policy as version 1. With --fresh it makes its own: psql drops and creates the
database enterplace_console_edit on the server --database names, and the check runs there. Uses browser_check.py's Chrome driver, the standard
library only. Exits 1 on the first check that fails.
"""
import argparse, json, os, pathlib, re, subprocess, sys, tempfile, time, urllib.parse, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from browser_check import CHROME, ROOT, Chrome, check, stop  # noqa: E402


def key_new(enterplace: str, folder: pathlib.Path, env: dict, name: str) -> str:
    out = subprocess.run([enterplace, "key", "new", name, "--team", "platform", "--admin", "--quiet",
                          "--policy", str(folder / "enterplace.policy.yaml")],
                         cwd=folder, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"enterplace key new failed: {out.stderr}")
    out = out.stdout
    found = re.search(r"enterplace_[0-9a-zA-Z_]+", out)
    if not found:
        raise SystemExit(f"enterplace key new printed no key: {out}")
    return found.group(0)


def fresh(url: str) -> str:
    """Drops and creates enterplace_console_edit on the server `url` names, with psql, and returns its URL."""
    parts = urllib.parse.urlsplit(url)
    for sql in ("DROP DATABASE IF EXISTS enterplace_console_edit", "CREATE DATABASE enterplace_console_edit"):
        out = subprocess.run(["psql", url, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], capture_output=True, text=True)
        if out.returncode != 0:
            raise SystemExit(f"psql could not run {sql}: {out.stderr.strip()}. Check --database and that psql is installed.")
    return urllib.parse.urlunsplit(parts._replace(path="/enterplace_console_edit"))


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
    parser.add_argument("--fresh", action="store_true", help="run in a new database enterplace_console_edit (needs psql)")
    parser.add_argument("--enterplace", default=str(ROOT / "target" / "debug" / "enterplace"))
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--port", type=int, default=20660)
    parser.add_argument("--out", default=str(ROOT / "target" / "console-edit-screens"))
    args = parser.parse_args()
    server = args.database if args.fresh else None
    if args.fresh:
        args.database = fresh(args.database)
    enterplace = str(pathlib.Path(args.enterplace).resolve())
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    folder = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-edit-"))
    base = f"http://127.0.0.1:{args.port}"
    (folder / "enterplace.policy.yaml").write_text(f"""version: 1
store: {{ postgres_url_env: ENTERPLACE_DATABASE_URL, policy_from: store, approval: true }}
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
audit: {{ path: enterplace-audit.jsonl }}
""")
    env = {**os.environ, "ENTERPLACE_DATABASE_URL": args.database}
    admin = key_new(enterplace, folder, env, "ops.admin")
    second = key_new(enterplace, folder, env, "noa.bar")
    subprocess.run([enterplace, "key", "new", "maya.cohen", "--team", "payments", "--quiet", "--policy",
                    str(folder / "enterplace.policy.yaml")], cwd=folder, env=env, capture_output=True, check=True)
    proc = subprocess.Popen([enterplace, "serve", str(folder / "enterplace.policy.yaml"), "--listen", f"127.0.0.1:{args.port}"],
                            cwd=folder, env=env, stdout=open(folder / "enterplace.log", "w"), stderr=subprocess.STDOUT)
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
        chrome.wait("location.pathname === '/console/app/' && location.hash.startsWith('#/overview')", "Overview after sign-in")

        # Prices: add a model through the app's dialog. Approval is on, so it waits; the second admin approves it.
        # The old address still opens the dialog.
        chrome.go(f"{base}/console/models?add=1", f"{base}/console/app/#/prices?add=1")
        chrome.wait("location.hash.startsWith('#/prices?add=1') && document.getElementById('model-name')", "the Add a model dialog")
        chrome.js("""(() => { const set = (id, v) => { const el = document.getElementById(id);
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
            el.dispatchEvent(new Event('input', { bubbles: true })); };
            set('model-name', 'local-fast'); set('model-input', '0.15'); set('model-output', '0.6'); set('model-aliases', 'fast');
            [...document.querySelectorAll('[role="dialog"] button')].find(b => b.textContent === 'Save version').click(); })()""")
        chrome.wait("[...document.querySelectorAll('[role=\"dialog\"] button')].some(b => b.textContent === 'Apply')", "the check before the save")
        chrome.js("[...document.querySelectorAll('[role=\"dialog\"] button')].find(b => b.textContent === 'Apply').click()")
        chrome.wait("document.body.textContent.includes('waits for a second admin')", "the new version waits for approval")
        status, body = api(base, second, "POST", "/admin/policy/versions/2/approve")
        check(status == 200, f"the second admin approves version 2 ({status} {body[:200]})")
        time.sleep(1.5)
        chrome.go(f"{base}/console/app/#/prices")
        chrome.wait("document.body.textContent.includes('local-fast')", "the approved model is listed")
        chrome.shot(out / "models.png")
        chrome.go(f"{base}/console/app/#/prices?price=local-large")
        chrome.wait("document.getElementById('price-input')", "the price dialog")
        chrome.shot(out / "models-price-dialog.png", full=False)
        chrome.size(390, 844)
        chrome.go(f"{base}/console/app/#/prices")
        chrome.wait("document.body.textContent.includes('local-fast')", "the Prices page on a phone")
        chrome.shot(out / "models-phone.png")
        chrome.size(1440)

        # The old address opens the app's Teams page.
        chrome.go(f"{base}/console/teams", f"{base}/console/app/#/teams")
        chrome.wait("location.hash.startsWith('#/teams') && document.body.textContent.includes('maya.cohen')", "teams list the people")
        chrome.shot(out / "teams.png")

        chrome.go(f"{base}/console/app/#/people")
        chrome.wait("[...document.querySelectorAll('main button')].some(b => b.textContent === 'Edit')", "the People page")
        chrome.js("[...document.querySelectorAll('main button')].find(b => b.textContent === 'Edit').click()")
        chrome.wait("location.hash.includes('edit=') && document.querySelector('[role=\"dialog\"]')", "the key editor")
        chrome.shot(out / "key-edit.png")

        # A draft that narrows everyone's models: dry-run from the editor, then saved for approval. The old address
        # opens the app's editor.
        chrome.go(f"{base}/console/policy/edit", f"{base}/console/app/#/policy/edit")
        chrome.wait("location.hash.startsWith('#/policy/edit') && document.getElementById('policy-text')", "the editor")
        chrome.js("""(() => { const set = (el, v, proto) => { Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
            el.dispatchEvent(new Event('input', { bubbles: true })); };
            const t = document.getElementById('policy-text');
            set(t, t.value.replace('principals: { any: true }\\n    models: [local-model]', 'principals: { any: true }\\n    models: []'), HTMLTextAreaElement.prototype);
            set(document.getElementById('policy-note'), 'everyone else gets no model', HTMLInputElement.prototype); })()""")
        chrome.js("[...document.querySelectorAll('main button')].find(b => b.textContent === 'Dry run').click()")
        chrome.wait("document.body.textContent.includes('Dry run done')", "the dry run")
        check("every gateway on the store" in chrome.js("document.body.textContent"),
              "the dry run replays every gateway's requests from the store")
        chrome.shot(out / "policy-edit-dry-run.png")
        chrome.js("[...document.querySelectorAll('main button')].find(b => b.textContent === 'Save for approval').click()")
        # Every save is checked first: its diff and a dry run of the last 24 hours, then Apply.
        chrome.wait("document.querySelector('[role=\"dialog\"]')?.textContent.includes('Dry run')", "the check before the save")
        chrome.shot(out / "policy-edit-check.png", full=False)
        chrome.js("[...document.querySelectorAll('[role=\"dialog\"] button')].find(b => b.textContent === 'Apply').click()")
        chrome.wait("location.hash.startsWith('#/policy/versions?version=') && document.body.textContent.includes('Waiting for approval')", "the saved draft")
        chrome.shot(out / "policy-version-pending.png")

        chrome.go(f"{base}/console/policy", f"{base}/console/app/#/policy/raw")
        chrome.wait("location.hash.startsWith('#/policy/raw') && document.getElementById('line-1')", "the raw policy")
        chrome.shot(out / "policy.png")
        chrome.go(f"{base}/console/policy/versions?version=2", f"{base}/console/app/#/policy/versions?version=2")
        chrome.wait("location.hash === '#/policy/versions?version=2' && document.body.textContent.includes('Changes from')", "version 2")
        chrome.shot(out / "policy-versions.png")
        print(f"console edit check passed; screenshots in {out}")
    except AssertionError as failed:
        print(f"FAILED: {failed}\nEnterplace's output: {folder / 'enterplace.log'}", file=sys.stderr)
        sys.exit(1)
    finally:
        if chrome:
            chrome.close()
        stop(proc)
        if server:
            # The database --fresh made goes with the run, so a test Postgres does not grow by one a run.
            subprocess.run(["psql", server, "-q", "-c", "DROP DATABASE IF EXISTS enterplace_console_edit WITH (FORCE)"],
                           capture_output=True, text=True)


if __name__ == "__main__":
    main()
