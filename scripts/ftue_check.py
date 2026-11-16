"""The new user's path, end to end and timed: install, start, the dashboard, a first request.

Usage: python3 scripts/ftue_check.py [--gantry target/release/gantry] [--chrome PATH] [--out DIR]

1. Installs the given gantry binary with install.sh from a local signed release (the fake release of
   scripts/install_check.sh, with this binary in the tarball), into a home of its own, and checks the PATH line went
   into its shell startup file.
2. Runs `gantry start --no-open` with no provider key: the first line printed must be the dashboard link.
3. Opens the link in headless Chrome (it signs in once), picks Coding agents, chooses Try without a key, runs the
   curl the page shows, and waits for the step to turn done by itself and the request to show in Requests.
4. Runs `gantry start --no-open` again in a new folder with GANTRY_OPENAI_BASE_URL pointing at a mock OpenAI,
   connects OpenAI in the console with a key, runs the curl, and checks the mock got that key and the request shows.
5. Claude subscriptions, the default answer of Coding agents: `gantry start` with GANTRY_ANTHROPIC_BASE_URL at a mock
   Anthropic, makes a person token on the checklist, checks "Copy for your agent" puts the token, the gateway and a
   docs .md link on the clipboard, sends a request as Claude Code on a subscription login does, and checks the mock
   got that login unchanged, the step turns done, and the login is in no file Gantry wrote. With --claude and the real
   `claude` CLI installed, Claude Code itself sends one prompt the same way: the mock answers and keeps only header
   names and the login's prefix and length, never its value, and nothing reaches Anthropic.

Prints how long each part took. Saves screenshots in --out. Uses browser_check.py's Chrome driver and the standard
library only. Exits 1 on the first check that fails.
"""
import argparse, http.server, json, os, pathlib, platform, re, shutil, socket, subprocess, sys, tarfile, tempfile, threading, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from browser_check import CHROME, ROOT, Chrome, check, stop  # noqa: E402

DEMO_TEXT = "Hello from the Gantry demo model"
MOCK_KEY = "sk-ftue-mock-key-0001"


class Mock(http.server.BaseHTTPRequestHandler):
    """A stand-in OpenAI: answers chat completions and keeps the Authorization header it was sent."""
    seen: list = []

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", "0")))
        Mock.seen.append(self.headers.get("authorization", ""))
        body = json.dumps({"id": "c", "object": "chat.completion", "model": "gpt-5",
                           "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello from the mock"}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


FAKE_LOGIN = "Bearer sk-ant-oat01-ftue-fake-subscription-login"


class Anthropic(http.server.BaseHTTPRequestHandler):
    """A stand-in Anthropic messages API. Keeps header names and the login's first 18 characters and length only."""
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or b"{}")
        auth = self.headers.get("authorization", "")
        Anthropic.seen.append({"path": self.path, "headers": sorted(k.lower() for k in self.headers.keys()),
                               "auth_prefix": auth[:18], "auth_len": len(auth),
                               "fake": auth == FAKE_LOGIN, "beta": self.headers.get("anthropic-beta", "")})
        model = body.get("model", "claude-sonnet-4-5")
        if self.path.startswith("/v1/messages/count_tokens"):
            out, kind = json.dumps({"input_tokens": 5}).encode(), "application/json"
        elif body.get("stream"):
            events = [
                ("message_start", {"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": None, "usage": {"input_tokens": 5, "output_tokens": 1}}}),
                ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello from the mock anthropic"}}),
                ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 6}}),
                ("message_stop", {"type": "message_stop"}),
            ]
            out, kind = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode(), "text/event-stream"
        else:
            out = json.dumps({"id": "m", "type": "message", "role": "assistant", "model": model,
                              "content": [{"type": "text", "text": "hello from the mock anthropic"}],
                              "stop_reason": "end_turn", "usage": {"input_tokens": 5, "output_tokens": 6}}).encode()
            kind = "application/json"
        self.send_response(200)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def target() -> str:
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}[platform.machine().lower()]
    return f"{arch}-{'apple-darwin' if sys.platform == 'darwin' else 'unknown-linux-musl'}"


def fake_release(work: pathlib.Path, gantry: str) -> pathlib.Path:
    """A signed release holding `gantry`, laid out as GitHub serves one, as scripts/install_check.sh makes it."""
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(work / "key")], check=True)
    public = " ".join((work / "key.pub").read_text().split()[:2])
    (work / "allowed_signers").write_text(f"release@gantry {public}\n")
    dist = work / "srv" / "releases" / "latest" / "download"
    dist.mkdir(parents=True)
    name = f"gantry-0.0.0-ftue-{target()}"
    with tarfile.open(dist / f"{name}.tar.gz", "w:gz") as tar:
        tar.add(gantry, arcname=f"{name}/gantry")
    env = {**os.environ, "GANTRY_SIGNING_KEY_FILE": str(work / "key"), "RELEASE_SIGNING_KEY": ""}
    subprocess.run([sys.executable, str(ROOT / "scripts" / "signing.py"), "sign", str(dist)], env=env, check=True, capture_output=True)
    return work / "srv"


def start(binary: pathlib.Path, folder: pathlib.Path, port: int, home: pathlib.Path, extra: dict):
    """`gantry start --no-open` with no provider key in its environment; returns the process and its first lines."""
    env = {"PATH": f"{binary.parent}:/usr/bin:/bin", "HOME": str(home), **extra}
    proc = subprocess.Popen(["gantry", "start", "--no-open", "--listen", f"127.0.0.1:{port}"], cwd=folder, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    head = []
    end = time.time() + 30
    while time.time() < end:
        line = proc.stdout.readline()
        if not line:
            break
        head.append(line.rstrip("\n"))
        if line.strip().startswith("export GANTRY_KEY="):
            break
    threading.Thread(target=lambda: [None for _ in proc.stdout], daemon=True).start()
    return proc, head


def link_and_key(head: list, port: int):
    first = next((l for l in head if l.strip()), "")
    check(first == "Gantry is running. Open the dashboard:", f"the first line printed is the dashboard link's (got {first!r})")
    link = next((l.strip() for l in head if l.strip().startswith(f"http://127.0.0.1:{port}/console/sign-in/")), "")
    key = next((l.strip().split("=", 1)[1] for l in head if l.strip().startswith("export GANTRY_KEY=")), "")
    check(bool(link) and key.startswith("gantry_"), "the link and the admin key are printed")
    return link, key


def click(chrome: Chrome, selector: str):
    chrome.js(f"document.querySelector({json.dumps(selector)}).click()")


def run_curl(lines: str, key: str) -> str:
    out = subprocess.run(["sh", "-c", lines], env={"PATH": "/usr/bin:/bin", "GANTRY_KEY": key}, capture_output=True, text=True, timeout=30)
    return out.stdout + out.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--gantry", default=str(ROOT / "target" / "release" / "gantry"))
    parser.add_argument("--chrome", default=CHROME)
    parser.add_argument("--out", default=str(ROOT / "target" / "ftue-screens"))
    parser.add_argument("--claude", action="store_true", help="also run the real claude CLI once against the mock Anthropic")
    args = parser.parse_args()
    if not shutil.which(args.chrome) and not pathlib.Path(args.chrome).exists():
        raise SystemExit(f"Chrome is not at {args.chrome}: pass --chrome with its path.")
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="gantry-ftue-"))
    home = work / "home"
    home.mkdir()
    procs = []
    began = time.monotonic()
    times = {}
    mark = lambda what: times.setdefault(what, time.monotonic() - began)
    try:
        # 1. Install.
        srv = fake_release(work, str(pathlib.Path(args.gantry).resolve()))
        port = free_port()
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), lambda *a: Quiet(*a, directory=str(srv)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        began = time.monotonic()
        installed = subprocess.run(["sh", str(ROOT / "install.sh")], capture_output=True, text=True,
                                   env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "SHELL": "/bin/zsh",
                                        "GANTRY_REPO_URL": f"http://127.0.0.1:{port}",
                                        "GANTRY_ALLOWED_SIGNERS": str(work / "allowed_signers")})
        check(installed.returncode == 0, f"install.sh installs gantry: {installed.stdout}{installed.stderr}")
        binary = home / ".local" / "bin" / "gantry"
        check(binary.exists(), "gantry is in ~/.local/bin")
        check(str(home / ".local" / "bin") in (home / ".zshrc").read_text(), "the install folder is on the PATH of new terminals (~/.zshrc)")
        mark("installed")

        # 2. Start, with no provider key.
        folder = work / "first"
        folder.mkdir()
        gport = free_port()
        proc, head = start(binary, folder, gport, home, {})
        procs.append(proc)
        link, key = link_and_key(head, gport)
        mark("started")

        # 3. The dashboard: sign in by the link, pick, try without a key, send the shown curl.
        chrome = Chrome(args.chrome, str(work / "chrome"))
        try:
            chrome.size(1280)
            chrome.call("Page.navigate", url=link)
            chrome.wait("location.pathname === '/console/start' && document.readyState === 'complete'", "Start here after the link")
            check("What do you want to start with?" in chrome.js("document.body.innerText"), "the link signed in and the welcome asks what to start with")
            chrome.shot(out / "1-welcome.png")
            mark("signed in")
            click(chrome, "button[data-start-button]")
            chrome.wait("document.querySelector('#step-1') && document.readyState === 'complete'", "the checklist")
            check("How does your team pay for Claude Code?" in chrome.js("document.body.innerText"), "Coding agents asks how the team pays")
            # The Anthropic API keys path: connect a model, then a first request with a key.
            chrome.go(f"http://127.0.0.1:{gport}/console/start?track=coding&pay=api")
            check("Connect a model" in chrome.js("document.body.innerText"), "the first step is Connect a model")
            chrome.shot(out / "2-connect.png")
            click(chrome, "form[action='/console/start/demo'] button")
            chrome.wait("document.querySelector('#step-1[data-state=done]') && document.querySelector('#lines-first')", "Connect a model done with the demo model")
            curl = chrome.js("document.getElementById('lines-first').innerText")
            check("gantry-demo" in curl and f"http://127.0.0.1:{gport}/v1/chat/completions" in curl, "the curl names the gateway and the demo model")
            chrome.shot(out / "3-first-request.png")
            answer = run_curl(curl, key)
            check(DEMO_TEXT in answer, f"the curl the page shows gets the demo answer: {answer[:300]}")
            mark("first request sent")
            chrome.wait("document.querySelector('#step-2[data-state=done]') || document.body.innerText.includes('Your first requests arrived')",
                        "Send your first request to turn done by itself", 15)
            mark("step done")
            chrome.shot(out / "4-first-data.png")
            chrome.go(f"http://127.0.0.1:{gport}/console/requests")
            check("gantry-demo" in chrome.js("document.body.innerText"), "the request is in Requests")
            chrome.shot(out / "5-requests.png")
        finally:
            chrome.close()

        # 4. A provider connected through the console, against a mock OpenAI.
        mock = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=mock.serve_forever, daemon=True).start()
        folder = work / "second"
        folder.mkdir()
        gport = free_port()
        proc, head = start(binary, folder, gport, home, {"GANTRY_OPENAI_BASE_URL": f"http://127.0.0.1:{mock.server_address[1]}/v1"})
        procs.append(proc)
        link, key = link_and_key(head, gport)
        chrome = Chrome(args.chrome, str(work / "chrome2"))
        try:
            chrome.size(1280)
            chrome.call("Page.navigate", url=link)
            chrome.wait("location.pathname === '/console/start' && document.readyState === 'complete'", "Start here after the link")
            click(chrome, "button[data-start-button]")
            chrome.wait("document.querySelector('#step-1') && document.readyState === 'complete'", "the checklist")
            chrome.go(f"http://127.0.0.1:{gport}/console/start?track=coding&pay=api")
            chrome.wait("document.querySelector('#connect-key')", "the Connect a model form")
            chrome.js(f"document.getElementById('connect-provider').value = 'openai'; document.getElementById('connect-key').value = {json.dumps(MOCK_KEY)}")
            click(chrome, "form[action='/console/start/connect'] button[type=submit]")
            chrome.wait("document.querySelector('#step-1[data-state=done]')", "Connect a model done with OpenAI")
            check("Connected:" in chrome.js("document.getElementById('step-1').innerText"), "OpenAI is connected")
            check(MOCK_KEY not in (folder / "gantry-credentials.json").read_text(), "the provider key is kept sealed")
            # The provider joins on the gateway's next read of the policy, within 2 seconds.
            time.sleep(2.5)
            chrome.go(f"http://127.0.0.1:{gport}/console/start?track=coding&pay=api")
            curl = chrome.js("document.getElementById('lines-first').innerText")
            check('"model":"gpt-5"' in curl, "the curl names the connected provider's model")
            chrome.shot(out / "6-connected.png")
            answer = run_curl(curl, key)
            check("hello from the mock" in answer, f"the request reaches the provider: {answer[:300]}")
            check(f"Bearer {MOCK_KEY}" in Mock.seen, "the provider got the key pasted in the console")
            chrome.wait("document.querySelector('#step-2[data-state=done]') || document.body.innerText.includes('Your first requests arrived')",
                        "Send your first request to turn done", 15)
            chrome.go(f"http://127.0.0.1:{gport}/console/requests")
            check("gpt-5" in chrome.js("document.body.innerText"), "the request is in Requests")
        finally:
            chrome.close()

        # 5. Claude subscriptions: no provider key, no API key, a person token and the person's own login.
        anthropic = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Anthropic)
        threading.Thread(target=anthropic.serve_forever, daemon=True).start()
        folder = work / "third"
        folder.mkdir()
        gport = free_port()
        proc, head = start(binary, folder, gport, home, {"GANTRY_ANTHROPIC_BASE_URL": f"http://127.0.0.1:{anthropic.server_address[1]}"})
        procs.append(proc)
        link, key = link_and_key(head, gport)
        gateway = f"http://127.0.0.1:{gport}"
        chrome = Chrome(args.chrome, str(work / "chrome3"))
        try:
            chrome.size(1280)
            try:
                chrome.call("Browser.grantPermissions", permissions=["clipboardReadWrite", "clipboardSanitizedWrite"], origin=gateway)
            except RuntimeError:
                pass  # this Chrome keeps the clipboard closed; the button's text is checked instead
            chrome.call("Page.navigate", url=link)
            chrome.wait("location.pathname === '/console/start' && document.readyState === 'complete'", "Start here after the link")
            click(chrome, "button[data-start-button]")
            chrome.wait("document.querySelector('#step-1[data-state=done]')", "Claude subscriptions on after gantry start")
            text = chrome.js("document.body.innerText")
            check("Claude subscription" in text and "ANTHROPIC_API_KEY=" not in text,
                  "subscriptions are the default and no API key is asked for")
            chrome.js("document.getElementById('token-name-sarah.miller').value = 'sarah.miller'; document.getElementById('token-team-sarah.miller').value = 'platform'")
            click(chrome, "form[action='/console/start/key'] button[type=submit]")
            chrome.wait("document.querySelector('#lines-subscription') && document.querySelector('#made-key')", "the person token and the lines")
            token = chrome.js("document.getElementById('made-key').innerText").strip()
            lines = chrome.js("document.getElementById('lines-subscription').innerText")
            check(token.startswith("gantry_u_"), f"a person token was made ({token[:12]}...)")
            check(f"export ANTHROPIC_BASE_URL={gateway}" in lines and f'ANTHROPIC_CUSTOM_HEADERS="x-gantry-user: {token}"' in lines,
                  "the lines are the base URL and the person token")
            chrome.shot(out / "7-subscriptions.png")
            click(chrome, "button[data-copy='agent-step-2']")
            time.sleep(0.5)
            # The clipboard when headless Chrome lets the page read it back, else the text the button copies.
            copied = chrome.js("navigator.clipboard.readText().catch(() => '')") or ""
            prompt = copied or chrome.js("document.getElementById('agent-step-2').textContent")
            check(chrome.js("document.querySelector(\"button[data-copy='agent-step-2']\").textContent") in ("Copied", "Copy for your agent"),
                  "the Copy for your agent button ran")
            check(token in prompt and gateway in prompt and "x-gantry-user" in prompt, "Copy for your agent holds the token and the gateway")
            md = re.search(r"https://gantry-docs\.eliran\.me/(\S+?)\.md", prompt)
            check(md is not None, "Copy for your agent links the docs as Markdown")
            built = ROOT / "docs" / "dist" / f"{md.group(1)}.md"
            if (ROOT / "docs" / "dist").exists():
                check(built.exists(), f"the docs build has {built.relative_to(ROOT)}")
            # What Claude Code on a subscription login sends.
            import urllib.request
            request = urllib.request.Request(f"{gateway}/v1/messages?beta=true", method="POST", data=json.dumps(
                {"model": "claude-sonnet-4-5", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]}).encode(),
                headers={"authorization": FAKE_LOGIN, "x-gantry-user": token, "anthropic-version": "2023-06-01",
                         "anthropic-beta": "claude-code-20250219,oauth-2025-04-20", "x-app": "cli",
                         "x-claude-code-session-id": "ftue-session", "content-type": "application/json",
                         "user-agent": "claude-cli/2.1.325 (external, cli)"})
            answer = urllib.request.urlopen(request, timeout=30).read().decode()
            check("hello from the mock anthropic" in answer, f"the request reaches Anthropic: {answer[:300]}")
            got = Anthropic.seen[-1]
            check(got["fake"] and "x-gantry-user" not in got["headers"] and "x-api-key" not in got["headers"],
                  "Anthropic got the caller's login unchanged, no person token and no key of Gantry's")
            chrome.go(f"{gateway}/console/start")
            chrome.wait("document.querySelector('#step-2[data-state=done]') || document.body.innerText.includes('Your first requests arrived')",
                        "Point Claude Code at Gantry to turn done", 15)
            chrome.go(f"{gateway}/console/requests")
            check("(est.)" in chrome.js("document.body.innerText"), "Requests shows the cost as an estimate")
            chrome.shot(out / "8-subscription-request.png")
        finally:
            chrome.close()
        written = "".join(p.read_text(errors="ignore") for p in folder.rglob("*") if p.is_file())
        check("sk-ant-oat01" not in written, "the login is in no file Gantry wrote")
        if args.claude and shutil.which("claude"):
            # Claude Code itself, on the subscription login of whoever runs this check. The mock keeps only header
            # names and the login's prefix and length; nothing goes to Anthropic.
            before = len(Anthropic.seen)
            env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
            env.update({"ANTHROPIC_BASE_URL": gateway, "ANTHROPIC_CUSTOM_HEADERS": f"x-gantry-user: {token}",
                        "ANTHROPIC_MODEL": "claude-sonnet-4-5", "ANTHROPIC_SMALL_FAST_MODEL": "claude-haiku-4-5",
                        "DISABLE_TELEMETRY": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"})
            ran = subprocess.run(["claude", "-p", "say hello"], env=env, capture_output=True, text=True, timeout=120)
            calls = Anthropic.seen[before:]
            print(f"  claude CLI: exit {ran.returncode}, {len(calls)} requests; login prefix {calls[-1]['auth_prefix'] if calls else '-'}..., length {calls[-1]['auth_len'] if calls else 0}")
            check(ran.returncode == 0 and "hello from the mock anthropic" in ran.stdout, f"Claude Code answered through Gantry: {ran.stdout[-300:]}{ran.stderr[-300:]}")
            check(any(c["auth_prefix"].startswith("Bearer sk-ant-oat") for c in calls), "Claude Code sent its own subscription login, passed on unchanged")
            check(all("x-gantry-user" not in c["headers"] for c in calls), "the person token never reached the provider")
            written = "".join(p.read_text(errors="ignore") for p in folder.rglob("*") if p.is_file())
            check("sk-ant-oat" not in written, "Claude Code's login is in no file Gantry wrote")
        elif args.claude:
            print("  skipped: the claude CLI is not installed")
        mark("subscription path")

        print("\nTimes from the start of the install (seconds):")
        for what, at in times.items():
            print(f"  {at:6.2f}  {what}")
        check(times["step done"] < 60, f"install to first data in under a minute ({times['step done']:.1f} s)")
    finally:
        for proc in procs:
            stop(proc)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
