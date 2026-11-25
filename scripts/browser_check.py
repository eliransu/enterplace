"""Signs in to the console in a real headless Chrome, issues a key, revokes it and verifies the chain.

Usage: python3 scripts/browser_check.py [--enterplace target/debug/enterplace] [--chrome PATH] [--port 20650]

The console's own tests set the Origin header by hand, so they cannot see what a browser really sends. This drives
Google Chrome over the DevTools protocol on a pipe (--remote-debugging-pipe), with the standard library only, and
types and presses keys as a person does. It also checks that a form posted from another site is refused, that the
one-time key fits its dialog at 1440 and 1024, and that a record sheet holds the keyboard. Exits 1 on the first
check that fails. Binds 127.0.0.1 only, and stops Enterplace and Chrome before it ends.
"""
import argparse, hashlib, http.server, json, os, pathlib, secrets, shutil, subprocess, sys, tempfile, threading, time, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHROME = {
    "darwin": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "linux": shutil.which("google-chrome") or shutil.which("chromium") or "google-chrome",
}.get(sys.platform, "chrome")


class Chrome:
    """One headless Chrome and one page in it, driven over --remote-debugging-pipe (fd 3 in, fd 4 out)."""

    def __init__(self, binary: str, profile: str):
        to_chrome, self._write = os.pipe()
        self._read, from_chrome = os.pipe()

        def fds():  # the pipe ends Chrome expects, at 3 and 4, moved out of the way first in case one is at 3 or 4
            high = os.dup(to_chrome), os.dup(from_chrome)
            os.dup2(high[0], 3)
            os.dup2(high[1], 4)

        self.proc = subprocess.Popen(
            [binary, "--headless=new", "--remote-debugging-pipe", f"--user-data-dir={profile}", "--no-first-run",
             "--no-default-browser-check", "--disable-extensions", "--hide-scrollbars", "about:blank"]
            # Ubuntu CI machines refuse the user namespaces Chrome's sandbox needs; the pages here are our own.
            + (["--no-sandbox"] if os.environ.get("CI") and sys.platform == "linux" else []),
            preexec_fn=fds, close_fds=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(to_chrome)
        os.close(from_chrome)
        self._buffer, self._next, self.session = b"", 0, None
        target = self.call("Target.createTarget", url="about:blank")["targetId"]
        self.session = self.call("Target.attachToTarget", targetId=target, flatten=True)["sessionId"]
        self.call("Page.enable")

    def call(self, method: str, **params):
        self._next += 1
        message = {"id": self._next, "method": method, "params": params}
        if self.session and not method.startswith("Target."):
            message["sessionId"] = self.session
        os.write(self._write, json.dumps(message).encode() + b"\0")
        while True:
            while b"\0" not in self._buffer:
                chunk = os.read(self._read, 1 << 16)
                if not chunk:
                    raise SystemExit("Chrome closed its pipe. Is it installed? Pass --chrome with its path.")
                self._buffer += chunk
            raw, self._buffer = self._buffer.split(b"\0", 1)
            reply = json.loads(raw)
            if reply.get("id") == self._next:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error']}")
                return reply.get("result", {})

    def js(self, expression: str):
        result = self.call("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise RuntimeError(f"{expression}: {result['exceptionDetails']}")
        return result["result"].get("value")

    def wait(self, expression: str, what: str, seconds: float = 10):
        end = time.time() + seconds
        while time.time() < end:
            try:
                if self.js(f"!!({expression})"):
                    return
            except RuntimeError:
                pass  # the page is between two loads
            time.sleep(0.1)
        said = self.js("(document.querySelector('[role=dialog], main') || document.body).innerText.slice(0, 600)")
        raise AssertionError(f"waited {seconds} s for {what}; the page is at {self.js('location.href')} and says: {said}")

    def go(self, url: str, landed: str = ""):
        """Opens `url` and waits for it, or for `landed` when the server redirects (an old page moved to the app)."""
        self.call("Page.navigate", url=url)
        self.wait(f"location.href === {json.dumps(landed or url)} && document.readyState === 'complete'", landed or url)

    def type(self, text: str):
        self.call("Input.insertText", text=text)

    def key(self, name: str, shift: bool = False):
        codes = {"Enter": (13, "\r"), "Tab": (9, ""), "Escape": (27, "")}
        code, text = codes[name]
        for kind in ("keyDown", "keyUp"):
            self.call("Input.dispatchKeyEvent", type=kind, key=name, code=name, windowsVirtualKeyCode=code,
                      text=text if kind == "keyDown" else "", modifiers=8 if shift else 0)

    def size(self, width: int, height: int = 900, scheme: str = "light"):
        self.call("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1,
                  mobile=width < 721)
        self.call("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": scheme}])

    def shot(self, path: pathlib.Path, full: bool = True):
        import base64
        self.js("document.fonts.ready.then(() => true)")
        params = {"format": "png", "captureBeyondViewport": full}
        if full:
            metrics = self.call("Page.getLayoutMetrics")["cssContentSize"]
            params["clip"] = {"x": 0, "y": 0, "width": metrics["width"], "height": metrics["height"], "scale": 1}
        path.write_bytes(base64.b64decode(self.call("Page.captureScreenshot", **params)["data"]))

    def close(self):
        stop(self.proc)


def stop(proc: subprocess.Popen):
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def check(ok: bool, what: str):
    if not ok:
        raise AssertionError(what)
    print(f"ok: {what}")


def serve(enterplace: str, folder: pathlib.Path, port: int) -> subprocess.Popen:
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
        raise SystemExit(f"Something already answers on 127.0.0.1:{port}. Stop it, or pass another --port.")
    except OSError:
        pass
    proc = subprocess.Popen([enterplace, "serve", str(folder / "enterplace.policy.yaml"), "--listen", f"127.0.0.1:{port}"],
                            cwd=folder, stdout=open(folder / "enterplace.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return proc
        except OSError:
            if proc.poll() is not None:
                raise SystemExit((folder / "enterplace.log").read_text())
            time.sleep(0.1)
    raise SystemExit("enterplace serve did not answer /healthz within 10 seconds")


def setup(folder: pathlib.Path, port: int) -> str:
    """A policy, and a keys file with one admin key, which is returned."""
    key = "enterplace_" + secrets.token_hex(32)
    (folder / "enterplace.policy.yaml").write_text(f"""version: 1
providers:
  - name: local
    kind: openai
    url: http://127.0.0.1:{port + 9}
    allow_private: true
    models: [local-model]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [local-model]
audit: {{ path: enterplace-audit.jsonl }}
""")
    (folder / "enterplace.keys.yaml").write_text(
        f"keys:\n  - name: ops.admin\n    team: platform\n    sha256: {hashlib.sha256(key.encode()).hexdigest()}\n    admin: true\n")
    return key


def other_site(port: int, target: str) -> http.server.ThreadingHTTPServer:
    """A page on another origin whose form posts to the console, as a cross-site attack would."""
    page = f"""<!doctype html><form method="post" action="{target}/console/sign-in"><input name="key" value="x"></form>
<script>document.forms[0].submit()</script>""".encode()

    class Page(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Page)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run(chrome: Chrome, base: str, key: str, enterplace: str, folder: pathlib.Path, evil: str):
    chrome.size(1440)
    # Sign in by typing the key and pressing Enter, as a person does.
    chrome.go(f"{base}/console/sign-in")
    chrome.js("document.getElementById('key').focus()")
    chrome.type(key)
    chrome.key("Enter")
    chrome.wait("location.pathname === '/console/app/' && location.hash.startsWith('#/overview')", "Overview after sign-in")
    check(True, "an admin key signs in from a real browser form")
    chrome.go(f"{base}/console/audit", f"{base}/console/app/#/audit")
    chrome.wait("document.querySelector('table a[href*=\"record=\"]')", "the audit log in the app")

    # A record sheet takes focus, keeps Tab inside, closes on Escape, and gives focus back to the row's link.
    opener = chrome.js("(() => { const a = document.querySelector('table a[href*=\"record=\"]'); a.click(); return a.getAttribute('href') })()")
    chrome.wait("document.querySelector('[role=\"dialog\"]') && document.readyState === 'complete'", "the record sheet")
    inside = "document.querySelector('[role=\"dialog\"]').contains(document.activeElement)"
    check(chrome.js(inside), "the record sheet has focus when it opens")
    for _ in range(12):
        chrome.key("Tab")
    check(chrome.js(inside), "Tab stays inside the record sheet")
    chrome.key("Escape")
    chrome.wait("!document.querySelector('[role=\"dialog\"]') && document.readyState === 'complete'", "the sheet to close on Escape")
    check(chrome.js("document.activeElement.getAttribute('href')") == opener, "focus is back on the link that opened the sheet")

    # Issue a key: name, Tab, team, Enter. The old address opens the console app's dialog.
    chrome.go(f"{base}/console/people?issue=1", f"{base}/console/app/#/people?issue=1")
    chrome.wait("document.getElementById('issue-name') && document.activeElement && document.activeElement.id === 'issue-name'", "the issue dialog")
    check(chrome.js("document.activeElement.id") == "issue-name", "the issue dialog puts focus in its first field")
    chrome.type("browser.check")
    chrome.key("Tab")
    chrome.type("qa")
    chrome.key("Enter")
    chrome.wait("document.getElementById('new-key')", "the new key")
    new_key = chrome.js("document.getElementById('new-key').textContent")
    check(new_key.startswith("enterplace_"), "a key is issued from a real browser form")
    for width in (1440, 1024, 390):
        chrome.size(width)
        fits = chrome.js("""(() => {
          const d = document.querySelector('[role="dialog"]').getBoundingClientRect();
          const inside = el => { const r = el.getBoundingClientRect(); return r.left >= d.left - 0.5 && r.right <= d.right + 0.5 };
          return inside(document.getElementById('new-key')) && inside(document.querySelector('[role="dialog"] [data-copy]'))
            && [...document.querySelectorAll('[role="dialog"] button')].every(inside)
            && document.documentElement.scrollWidth <= innerWidth })()""")
        check(fits, f"the key, Copy and Done stay inside the dialog at {width}")
    chrome.size(1440)

    # Revoke it: type the name, Enter.
    sha = hashlib.sha256(new_key.encode()).hexdigest()
    chrome.go(f"{base}/console/people?revoke={sha}", f"{base}/console/app/#/people?revoke={sha}")
    chrome.wait("document.getElementById('revoke-type') && document.activeElement && document.activeElement.id === 'revoke-type'", "the revoke dialog")
    chrome.type("browser.check")
    chrome.key("Enter")
    chrome.wait("!location.hash.includes('revoke=')", "the revoke to finish")
    check(sha not in (folder / "enterplace.keys.yaml").read_text(), "the key is revoked from a real browser form")

    # Verify the chain, and check the hash the console shows with the CLI.
    chrome.go(f"{base}/console/audit", f"{base}/console/app/#/audit")
    chrome.wait("[...document.querySelectorAll('button')].some(b => b.textContent.includes('Verify chain now'))", "the audit log in the app")
    chrome.js("[...document.querySelectorAll('button')].find(b => b.textContent.includes('Verify chain now')).click()")
    chrome.wait("document.getElementById('last-hash')", "the verified chain")
    last = chrome.js("document.getElementById('last-hash').textContent")
    out = subprocess.run([enterplace, "audit", "verify", str(folder / "enterplace-audit.jsonl"), "--expect-last", last],
                         capture_output=True, text=True)
    check(out.returncode == 0 and len(last) == 64,
          f"the console's last hash passes enterplace audit verify --expect-last ({out.stdout.strip() or out.stderr.strip()})")

    # A form from another site is refused, with the console's own page.
    chrome.go(evil)
    chrome.wait("location.pathname === '/console/sign-in' && document.readyState === 'complete'", "the cross-site post")
    check(chrome.js("document.querySelector('.g-empty__title')?.textContent") == "This form came from somewhere else",
          "a form posted from another site is refused with the console's error page")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--enterplace", default=str(ROOT / "target" / "debug" / "enterplace"))
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--port", type=int, default=20650)
    args = parser.parse_args()
    args.enterplace = str(pathlib.Path(args.enterplace).resolve())  # Enterplace runs in its own folder
    folder = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-browser-"))
    key = setup(folder, args.port)
    enterplace = serve(args.enterplace, folder, args.port)
    evil, chrome = None, None
    try:
        evil = other_site(args.port + 1, f"http://127.0.0.1:{args.port}")
        chrome = Chrome(args.chrome, str(folder / "chrome"))
        run(chrome, f"http://127.0.0.1:{args.port}", key, args.enterplace, folder, f"http://127.0.0.1:{args.port + 1}/")
        print("browser check passed")
    except AssertionError as failed:
        print(f"FAILED: {failed}\nEnterplace's output: {folder / 'enterplace.log'}", file=sys.stderr)
        sys.exit(1)
    finally:
        if chrome:
            chrome.close()
        if evil:
            evil.shutdown()
        stop(enterplace)
    shutil.rmtree(folder, ignore_errors=True)


if __name__ == "__main__":
    main()
