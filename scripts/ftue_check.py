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
            chrome.wait("document.querySelector('#connect-key')", "the Connect a model form")
            chrome.js(f"document.getElementById('connect-provider').value = 'openai'; document.getElementById('connect-key').value = {json.dumps(MOCK_KEY)}")
            click(chrome, "form[action='/console/start/connect'] button[type=submit]")
            chrome.wait("document.querySelector('#step-1[data-state=done]')", "Connect a model done with OpenAI")
            check("Connected:" in chrome.js("document.getElementById('step-1').innerText"), "OpenAI is connected")
            check(MOCK_KEY not in (folder / "gantry-credentials.json").read_text(), "the provider key is kept sealed")
            # The provider joins on the gateway's next read of the policy, within 2 seconds.
            time.sleep(2.5)
            chrome.go(f"http://127.0.0.1:{gport}/console/start")
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
