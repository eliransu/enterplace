"""Runs the Gantry image against a mock provider on this machine and times the first governed request.

Usage: python3 scripts/smoke_image.py gantry:<version>
Passes when the image runs as a user other than root, is under 50 MB, prints the same version and source hash as
target/release/gantry-enterprise (when that exists), answers a governed request within 60 seconds of `docker run`,
leaving one request record in an unbroken chain, answers /healthz and /readyz, and without a license key says it runs
the open source edition (`license show` and the license in /healthz). Then the quickstart's `docker run` (the default
command, no provider key): the log's first line is the dashboard link, the demo model answers with the admin key it
printed, and the link signs in.
SMOKE_MOCK_PORT and SMOKE_PORT pick the mock's port and the port the container is published on (both on
127.0.0.1); unset, the system picks free ones."""
import http.server, json, os, shutil, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request

image = sys.argv[1]
size = int(subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Size}}"]).decode())
user = subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Config.User}}"]).decode().strip()
assert size < 50 * 1024 * 1024, f"the image is {size} bytes, over 50 MB"
assert user and not user.startswith("0") and user != "root", f"the image runs as {user!r}"
# The image must be this tree's build: the same source hash as the local binary, when there is one.
local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "gantry-enterprise")
if os.path.exists(local):
    mine = subprocess.check_output([local, "version"]).decode().split(", built")[0]
    theirs = subprocess.check_output(["docker", "run", "--rm", image, "version"]).decode().split(", built")[0]
    assert mine == theirs, f"the image is {theirs!r}, this tree's binary is {mine!r}: rebuild the image"

class Mock(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        out = json.dumps({"id": "chatcmpl-mock", "choices": [{"message": {"role": "assistant", "content": "ok"}}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass

# Loopback only: Docker Desktop's host.docker.internal reaches the host's 127.0.0.1.
mock = http.server.ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("SMOKE_MOCK_PORT", "0"))), Mock)
threading.Thread(target=mock.serve_forever, daemon=True).start()
work = tempfile.mkdtemp()
policy = f"""version: 1
providers:
  - name: mock
    kind: openai
    url: http://host.docker.internal:{mock.server_port}
    allow_private: true
    key_env: MOCK_KEY
    models: [gpt-4o-mini]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [gpt-4o-mini]
audit: {{ path: /var/lib/gantry/gantry-audit.jsonl }}
"""
open(os.path.join(work, "gantry.policy.yaml"), "w").write(policy)
# The keys live in a writable folder, as docs/quickstart.md teaches: the console and the admin API write there.
keys_dir = os.path.join(work, "keys")
os.makedirs(keys_dir)
key = subprocess.check_output(["docker", "run", "--rm", "-v", f"{keys_dir}:/work", "-w", "/work", "--user", f"{os.getuid()}",
                               image, "key", "new", "smoke", "--team", "t", "--keys", "/work/gantry.keys.yaml"]).decode()
key = next(word for word in key.split() if word.startswith("gantry_"))
volume = f"gantry-smoke-{os.getpid()}"
started = time.monotonic()
container = subprocess.check_output(["docker", "run", "-d", "--rm", "-p", f"127.0.0.1:{os.environ.get('SMOKE_PORT', '')}:8080",
    "--add-host", "host.docker.internal:host-gateway", "-e", "MOCK_KEY=k",
    "-v", f"{work}/gantry.policy.yaml:/etc/gantry/gantry.policy.yaml:ro",
    "-v", f"{keys_dir}:/etc/gantry/keys",
    "-v", f"{volume}:/var/lib/gantry", image,
    "serve", "/etc/gantry/gantry.policy.yaml", "--keys", "/etc/gantry/keys/gantry.keys.yaml", "--listen", "0.0.0.0:8080"]).decode().strip()
try:
    port = subprocess.check_output(["docker", "port", container, "8080"]).decode().split(":")[-1].strip()
    body = json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}).encode()
    while True:
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{port}/v1/chat/completions", body,
                                             {"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=2) as answer:
                assert answer.status == 200 and answer.headers["X-Gantry-Decision"]
                break
        except (OSError, AssertionError):
            if time.monotonic() - started > 60:
                raise SystemExit("no governed answer within 60 seconds of docker run")
            time.sleep(0.2)
    took = time.monotonic() - started
    records = subprocess.check_output(["docker", "exec", container, "/gantry", "audit", "verify", "/var/lib/gantry/gantry-audit.jsonl"]).decode()
    # One request record, besides the configuration record of the start and the request's usage record.
    assert "1 request," in records, records
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as answer:
        health = json.loads(answer.read())
        assert answer.status == 200, health
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=5) as answer:
        assert answer.status == 200
    # No license key in the container: the open source edition, said both ways.
    assert health.get("license", {}).get("state") == "missing", health
    shown = subprocess.check_output(["docker", "run", "--rm", image, "license", "show"]).decode()
    assert "No license: running the open source features only" in shown, shown
    # The quickstart's docker run: no policy, no provider key. The log opens with the dashboard link.
    quick = subprocess.check_output(["docker", "run", "-d", "--rm", "-p", "127.0.0.1::8080", "-v", f"{volume}-quick:/var/lib/gantry", image]).decode().strip()
    try:
        qport = subprocess.check_output(["docker", "port", quick, "8080"]).decode().split(":")[-1].strip()
        deadline = time.monotonic() + 30
        log = ""
        while "export GANTRY_KEY=" not in log and time.monotonic() < deadline:
            time.sleep(0.3)
            log = subprocess.run(["docker", "logs", quick], capture_output=True, text=True).stdout
        first = next((l for l in log.splitlines() if l.strip()), "")
        assert first == "Gantry is running. Open the dashboard:", log
        assert "docker restart gantry" in log and "--force" not in log, log
        qkey = next(w for w in log.split() if w.startswith("GANTRY_KEY=")).split("=", 1)[1]
        link = next(w for w in log.split() if "/console/sign-in/" in w)
        demo = json.dumps({"model": "gantry-demo", "messages": [{"role": "user", "content": "hi"}]}).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{qport}/v1/chat/completions", demo,
                                         {"Authorization": f"Bearer {qkey}", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as answer:
            assert b"Gantry demo model" in answer.read()
        class Stay(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            urllib.request.build_opener(Stay).open(link.replace("127.0.0.1:8080", f"127.0.0.1:{qport}"), timeout=5)
            raise SystemExit("the sign-in link did not redirect")
        except urllib.error.HTTPError as err:
            assert err.code == 303 and err.headers["location"] == "/console/start", (err.code, err.headers)
    finally:
        subprocess.run(["docker", "rm", "-f", quick], capture_output=True)
        subprocess.run(["docker", "volume", "rm", f"{volume}-quick"], capture_output=True)
    print(f"pass: {size / 1e6:.1f} MB, user {user}, first governed request {took:.1f} s after docker run, {records.splitlines()[0]}; /healthz and /readyz 200, license {health['license']['state']} (open source edition); the quickstart's docker run prints the link first and the demo model answers")
finally:
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    subprocess.run(["docker", "volume", "rm", volume], capture_output=True)
    shutil.rmtree(work, ignore_errors=True)
