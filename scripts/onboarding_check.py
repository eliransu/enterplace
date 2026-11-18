"""Walks the console's first run in a real headless Chrome against a local gateway and a mock provider.

Usage: python3 scripts/onboarding_check.py [--enterplace target/debug/enterplace] [--out DIR]

An empty install: one admin key, a policy in observe mode, the provider pointed at a mock on this machine. The check
signs in, sees the welcome, screenshots every empty page, picks coding agents, makes a key for the first request in
the console app, sends a real request with that key through the gateway mid-flow and waits, without reloading, for
the step to turn done on its own. Then it adds two people, asks for the five steps and screenshots each state, at
1440 wide and 390 wide, light and dark. Uses browser_check.py's Chrome driver, the standard library only. Exits 1 on the first check that fails.
"""
import argparse, hashlib, http.server, json, pathlib, secrets, socket, sys, tempfile, threading, time, urllib.error, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from browser_check import CHROME, ROOT, Chrome, check, serve, stop  # noqa: E402


class Provider(http.server.BaseHTTPRequestHandler):
    """Answers every chat request, with token counts so the request has a cost."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", "0")))
        body = json.dumps({"id": "c", "object": "chat.completion", "model": "local-model",
                           "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1200, "completion_tokens": 300, "total_tokens": 1500}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ask(base: str, key: str):
    """One chat request through the gateway, as a coding tool sends it."""
    body = json.dumps({"model": "local-model", "messages": [{"role": "user", "content": "hello"}]}).encode()
    request = urllib.request.Request(f"{base}/v1/chat/completions", data=body, method="POST", headers={
        "authorization": f"Bearer {key}", "content-type": "application/json", "user-agent": "claude-cli/2.1.0"})
    # A new key works within 2 seconds, when the gateway reads the keys file again.
    for _ in range(50):
        try:
            with urllib.request.urlopen(request, timeout=10) as answer:
                return answer.status
        except urllib.error.HTTPError as err:
            if err.code != 401:
                return err.code
            time.sleep(0.1)
    return 401


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--enterplace", default=str(ROOT / "target" / "debug" / "enterplace"))
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--out", default=str(ROOT / "target" / "onboarding-screens"))
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    folder = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-onboarding-"))
    (folder / "enterplace.policy.yaml").write_text(f"""version: 1
mode: observe
providers:
  - name: local
    kind: openai
    url: http://127.0.0.1:{provider.server_address[1]}
    allow_private: true
    models: [local-model]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: ["*"]
prices:
  local-model: {{ input: 3, output: 15 }}
audit: {{ path: enterplace-audit.jsonl }}
""")
    admin = "enterplace_" + secrets.token_hex(32)
    (folder / "enterplace.keys.yaml").write_text(
        f"keys:\n  - name: alex.rivera\n    team: platform\n    sha256: {hashlib.sha256(admin.encode()).hexdigest()}\n    admin: true\n")
    proc = serve(str(pathlib.Path(args.enterplace).resolve()), folder, port)
    chrome = None

    def shots(name: str, phone: bool = True, dark: bool = False):
        chrome.shot(out / f"{name}.png")
        if dark:
            chrome.size(1440, scheme="dark")
            chrome.go(chrome.js("location.href"))
            chrome.shot(out / f"{name}-dark.png")
            chrome.size(1440)
        if phone:
            chrome.size(390, 844)
            chrome.go(chrome.js("location.href"))
            chrome.shot(out / f"{name}-phone.png")
            chrome.size(1440)
            chrome.go(chrome.js("location.href"))

    try:
        chrome = Chrome(args.chrome, str(folder / "chrome"))
        chrome.size(1440)
        chrome.go(f"{base}/console/sign-in")
        chrome.js("document.getElementById('key').focus()")
        chrome.type(admin)
        chrome.key("Enter")
        # Start here is a page of the console app: sign-in lands on its route.
        chrome.wait("location.pathname === '/console/app/' && location.hash.startsWith('#/start') && !!document.querySelector('[data-start-button]')",
                    "Start here after sign-in")
        text = chrome.js("document.body.innerText")
        check("What do you want to start with?" in text and chrome.js("!!document.querySelector('[data-welcome]') && getComputedStyle(document.querySelector('nav[aria-label=Console]')).display === 'none'"),
              "an empty install opens on the welcome, with no nav")
        check(f"Running at {base}" in text, "the welcome names the gateway's address")
        chrome.js("document.querySelector('input[value=apps]').click()")
        chrome.wait("document.querySelector('[data-start-button]').textContent === 'Start with our apps'", "the button following the choice")
        chrome.js("document.querySelector('input[value=coding]').click()")
        shots("1-welcome", dark=True)

        for path, title in [("requests", "No requests yet"), ("analytics", "Nothing to rank yet"), ("spend", "No spend and no budgets yet"),
                            ("people", "Only your admin key so far"), ("teams", "No teams yet"), ("policy", "One rule lets everyone in"),
                            ("mcp/approvals", "No MCP servers yet"), ("audit", "Only setup records so far")]:
            # Every page moved to the console app: the old address lands there, and the page fills in after its first
            # read. The policy page is the app's raw policy.
            route = "policy/raw" if path == "policy" else path
            chrome.go(f"{base}/console/{path}", f"{base}/console/app/#/{route}")
            chrome.wait(f"document.body.innerText.includes({title!r})", f"the {path} page")
            check(title in chrome.js("document.body.innerText") and chrome.js("!!document.querySelector('.g-empty a.g-btn[href^=\"/console/start\"], main a[href^=\"/console/start\"]')"),
                  f"{path} says what fills it and opens the Start here step")
            chrome.shot(out / f"4-empty-{path.replace('/', '-')}.png")
        chrome.size(390, 844)
        chrome.go(f"{base}/console/people", f"{base}/console/app/#/people")
        chrome.wait("document.body.innerText.includes('Only your admin key so far')", "the People page")
        chrome.shot(out / "4-empty-people-phone.png")
        chrome.size(1440)

        chrome.go(f"{base}/console/start", f"{base}/console/app/#/start")
        chrome.wait("!!document.querySelector('[data-start-button]')", "the pick")
        chrome.js("document.querySelector('[data-start-button]').click()")
        chrome.wait("document.querySelector('[data-checklist]')", "the coding agents checklist")
        # API keys are the default way to pay; the policy has a provider, so Connect a model is done.
        check("Coding agents: 1 of 6 done" in chrome.js("document.body.innerText"), "the choice opens its checklist")
        shots("2-checklist-nothing", dark=True)

        # The first request: a key made for it goes into the lines, shown once.
        click = "(label => [...document.querySelectorAll('main button')].find(b => b.textContent === label).click())"
        chrome.js(f"{click}('Make a key for this request')")
        chrome.wait("/Bearer enterplace_/.test(document.getElementById('lines-first')?.textContent ?? '')", "the key in the first request's lines")
        lines = chrome.js("document.getElementById('lines-first').textContent")
        first = lines.split("Bearer ", 1)[1].split('"', 1)[0]
        check(first.startswith("enterplace_") and f"curl {base}/v1/chat/completions" in lines, "the key made is in the lines to paste, with the gateway's address")
        check(chrome.js("document.querySelector('[data-state=listening]')?.textContent.includes('Waiting for the first request')"),
              "the step listens for the first request")
        shots("2-checklist-waiting", phone=False)

        # A real request through the gateway, mid-flow: the page's poll sees it and the step turns done by itself.
        check(ask(base, first) == 200, "a request with the new key goes through the gateway")
        chrome.wait("document.body.innerText.includes('Your first requests arrived')", "step 2 turning done without a reload", seconds=15)
        text = chrome.js("document.body.innerText")
        check("Your first requests arrived" in text and "in the last 10 minutes" in text, "the first requests show on Start here")
        shots("3-first-data", dark=True)

        def person(name: str, team: str) -> str:
            chrome.wait("!!document.querySelector('form[data-action=key]')", f"the key form for {name}")
            chrome.js(f"""(() => {{ const f = document.querySelector('form[data-action=key]');
                f.querySelector('[name=name]').value = {name!r}; f.querySelector('[name=team]').value = {team!r}; f.requestSubmit(); }})()""")
            chrome.wait(f"document.body.innerText.includes('made for {name}') && !!document.querySelector('#made-key')", f"the key of {name}")
            key = chrome.js("document.getElementById('made-key').textContent")
            check(key.startswith("enterplace_"), f"the key of {name} is shown once")
            return key

        sarah = person("sarah.miller", "platform")
        check(sarah in chrome.js("document.getElementById('lines-coding').textContent"), "the key made is in the coding agent's lines")
        check(ask(base, sarah) == 200, "the first person's request goes through")
        chrome.wait("document.body.innerText.includes('Add a second person') && document.querySelector('[data-state=now]')?.textContent.includes('Add a second person')",
                    "the first person's step turning done without a reload", seconds=15)
        second = person("mike.johnson", "payments")
        check(ask(base, second) == 200, "the second person's request goes through")
        chrome.wait("!!document.querySelector('[data-five-steps]')", "the checklist complete", seconds=15)
        shots("2-checklist-done", phone=False)
        chrome.js("document.querySelector('[data-five-steps]').click()")
        chrome.wait("document.querySelector('[data-stages]')", "the five steps")
        text = chrome.js("document.body.innerText")
        check(all(w in text for w in ["See", "Know", "Limit", "Protect", "Prove", "Also start with"]), "the five steps take the page")
        shots("5-five-steps", dark=True)
        print(f"onboarding check passed; screenshots in {out}")
    except AssertionError as failed:
        print(f"FAILED: {failed}\nEnterplace's output: {folder / 'enterplace.log'}", file=sys.stderr)
        sys.exit(1)
    finally:
        if chrome:
            chrome.close()
        stop(proc)
        provider.shutdown()


if __name__ == "__main__":
    main()
