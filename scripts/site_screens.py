"""The console screenshots on enterplace.dev, taken again from the console as it is now, on made-up records.

Usage: python3 scripts/site_screens.py [--enterplace target/debug/enterplace] [--chrome PATH] [--database URL]
       [--out site/src/static/img] [--port 20780]

Runs `enterplace demo-seed --fake-records` (five weeks of made-up usage in a real audit chain) in a temporary folder,
serves it, signs in to the console in headless Chrome and saves each page the site shows as a WebP, light and, where
the site shows both, dark. With --database (a Postgres the script may create a database in) it also serves a copy
whose policy is kept in the store with approval on, for the "Edit the policy" shot with its dry run; without it that
shot is skipped and the old file is kept. Run `python3 build.py` in site/ afterwards to copy them into site/public.

Each shot is the whole page at 1440 pixels wide: the window is made as tall as the page, so the sidebar and header
stay where a reader sees them. Uses browser_check.py's Chrome driver and the standard library only.
"""
import argparse, base64, os, pathlib, re, shutil, subprocess, sys, tempfile, time, urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from browser_check import CHROME, ROOT, Chrome, stop  # noqa: E402

WIDTH = 1440
# The callers the New and pending shot leaves for an admin to decide: one app, one person.
PENDING = ["search-indexer", "noa.bar"]


def seed(enterplace: str, folder: pathlib.Path) -> str:
    out = subprocess.run([enterplace, "demo-seed", str(folder), "--fake-records"], capture_output=True, text=True,
                         check=True).stdout
    found = re.search(r"enterplace_[0-9a-f]{64}", out)
    if not found:
        raise SystemExit(f"demo-seed printed no admin key:\n{out}")
    return found.group(0)


def hold_new_callers(folder: pathlib.Path):
    """New callers held for approval, every seeded caller allowed but PENDING, as an install that turned it on."""
    names = re.findall(r"^  - name: (\S+)", (folder / "enterplace.keys.yaml").read_text(), re.M)
    allowed = [n for n in names if n not in PENDING and n != "demo.admin"]
    policy = folder / "enterplace.policy.yaml"
    policy.write_text(policy.read_text() + f"new_callers:\n  mode: hold\n  allowed: [{', '.join(allowed)}]\n")


def serve(enterplace: str, folder: pathlib.Path, port: int, env: dict | None = None) -> subprocess.Popen:
    log = open(folder / "serve.log", "w")
    proc = subprocess.Popen([enterplace, "serve", "enterplace.policy.yaml", "--listen", f"127.0.0.1:{port}"],
                            cwd=folder, stdout=log, stderr=subprocess.STDOUT, env={**os.environ, **(env or {})})
    import urllib.request
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return proc
        except OSError:
            time.sleep(0.2)
    stop(proc)
    raise SystemExit(f"Enterplace did not start: {(folder / 'serve.log').read_text()}")


def sign_in(chrome: Chrome, base: str, key: str):
    chrome.size(WIDTH, 900)
    chrome.go(f"{base}/console/sign-in")
    chrome.js("document.getElementById('key').focus()")
    chrome.type(key)
    chrome.key("Enter")
    chrome.wait("location.hash.startsWith('#/overview')", "Overview after sign-in")


def settle(chrome: Chrome, ready: str):
    chrome.wait(ready, "the page's content", 20)
    # Charts draw and live counts land after the data; a toast would cover a corner.
    time.sleep(1.5)
    chrome.js("document.querySelectorAll('[data-sonner-toaster]').forEach(t => t.remove())")
    chrome.js("document.fonts.ready.then(() => true)")


def save(chrome: Chrome, path: pathlib.Path, scheme: str):
    chrome.size(WIDTH, 900, scheme)
    time.sleep(0.5)
    height = chrome.js("Math.ceil(Math.max(document.documentElement.scrollHeight, document.body.scrollHeight))")
    chrome.size(WIDTH, height, scheme)
    time.sleep(0.5)
    data = chrome.call("Page.captureScreenshot", format="webp", quality=88)["data"]
    path.write_bytes(base64.b64decode(data))
    print(f"{path.name}: {WIDTH}x{height}")
    chrome.size(WIDTH, 900, "light")


def page(chrome: Chrome, base: str, route: str, ready: str):
    chrome.size(WIDTH, 900)
    chrome.call("Page.navigate", url=f"{base}/console/app/#/{route}")
    chrome.wait(f"location.hash === '#/{route}'", route)
    settle(chrome, ready)


def shots(chrome: Chrome, base: str, out: pathlib.Path):
    page(chrome, base, "overview", "document.querySelector('main') && /Spend this month/.test(document.querySelector('main').innerText)")
    save(chrome, out / "console-overview-light.webp", "light")
    save(chrome, out / "console-overview-dark.webp", "dark")
    page(chrome, base, "usage/spend", "/Who spent most/.test(document.querySelector('main')?.innerText || '')")
    save(chrome, out / "console-spend-light.webp", "light")
    page(chrome, base, "audit", "document.querySelector('table a[href*=\"record=\"]')")
    save(chrome, out / "console-audit-light.webp", "light")
    save(chrome, out / "console-audit-dark.webp", "dark")
    page(chrome, base, "apps/new", "/pending/i.test(document.querySelector('main')?.innerText || '')")
    save(chrome, out / "console-new-callers-light.webp", "light")


def dry_run(chrome: Chrome, base: str, out: pathlib.Path):
    page(chrome, base, "policy/edit", "document.querySelector('textarea')")
    # The payments rule's budget cut to 5 cents a day: the dry run shows the recent requests it would refuse. A rule's
    # budget, not a limits: entry, since the dry run replays the budgets of rules.
    chrome.js("""(() => {
      const ta = document.querySelector('textarea');
      const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
      set.call(ta, ta.value.replace('budget: { usd: 400, per: month }', 'budget: { usd: 0.05, per: day }'));
      ta.dispatchEvent(new Event('input', { bubbles: true }));
      return true })()""")
    if not chrome.js("document.querySelector('textarea').value.includes('usd: 0.05, per: day')"):
        raise SystemExit("The seeded policy no longer has the payments rule budget this shot changes: update dry_run().")
    hours = chrome.js("[...document.querySelectorAll('input')].findIndex(i => i.value === '24')")
    if hours is not None and hours >= 0:
        # Two hours, for a few rows: the seed's older refusals are made up under a different policy and would read as noise.
        chrome.js(f"""(() => {{ const i = document.querySelectorAll('input')[{hours}];
          Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, '2');
          i.dispatchEvent(new Event('input', {{ bubbles: true }})); return true }})()""")
    chrome.js("[...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Dry run').click()")
    settle(chrome, "/requests replayed/.test(document.querySelector('main')?.innerText || '')")
    chrome.js("window.scrollTo(0, 0)")
    save(chrome, out / "console-policy-dry-run-light.webp", "light")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--enterplace", default=str(ROOT / "target" / "debug" / "enterplace"))
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--database", help="Postgres URL for the Edit the policy shot, such as postgres://postgres:pw@127.0.0.1:5432/postgres")
    parser.add_argument("--out", default=str(ROOT / "site" / "src" / "static" / "img"))
    parser.add_argument("--port", type=int, default=20780)
    args = parser.parse_args()
    enterplace, out = str(pathlib.Path(args.enterplace).resolve()), pathlib.Path(args.out).resolve()
    work = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-screens-"))
    procs, chrome = [], None
    try:
        files = work / "files"
        key = seed(enterplace, files)
        hold_new_callers(files)
        procs.append(serve(enterplace, files, args.port))
        chrome = Chrome(args.chrome, str(work / "chrome"))
        base = f"http://127.0.0.1:{args.port}"
        sign_in(chrome, base, key)
        shots(chrome, base, out)
        if args.database:
            store = work / "store"
            store_key = seed(enterplace, store)
            policy = store / "enterplace.policy.yaml"
            policy.write_text(policy.read_text() + "store: { postgres_url_env: DATABASE_URL, policy_from: store, approval: true }\n")
            url = urllib.parse.urlsplit(args.database)
            name = f"enterplace_screens_{os.getpid()}"
            admin = f"{url.scheme}://{url.netloc}/postgres"
            subprocess.run(["psql", admin, "-qc", f"DROP DATABASE IF EXISTS {name}", "-c", f"CREATE DATABASE {name}"], check=True)
            env = {"DATABASE_URL": f"{url.scheme}://{url.netloc}/{name}?sslmode=disable"}
            subprocess.run([enterplace, "store", "import", "--keys", "enterplace.keys.yaml", "--policy", "enterplace.policy.yaml"],
                           cwd=store, env={**os.environ, **env}, check=True, capture_output=True)
            procs.append(serve(enterplace, store, args.port + 1, env))
            sign_in(chrome, f"http://127.0.0.1:{args.port + 1}", store_key)
            dry_run(chrome, f"http://127.0.0.1:{args.port + 1}", out)
        else:
            print("console-policy-dry-run-light.webp: kept, pass --database to take it again")
    finally:
        if chrome:
            chrome.close()
        for proc in procs:
            stop(proc)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
