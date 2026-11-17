"""Upgrade and rollback on the same data: the acceptance check of package 7.2.

Usage: python3 scripts/rollback_check.py <old enterplace binary> <new enterplace binary>
Runs the old version, upgrades to the new one, then rolls back to the old one, all on one folder holding the
policy, the keys file and the audit log, as a deployment's volume does. Each version serves governed requests
through a local mock provider. Passes when every request succeeds, a key issued by the new version still works
after the rollback, and both binaries verify the whole audit chain, records from either version included.
Standard library only.
"""
import http.server, json, os, pathlib, signal, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request

FAILED = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n      {detail}"))
    if not ok:
        FAILED.append(name)


class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", "0")))
        body = json.dumps({"id": "x", "object": "chat.completion", "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(binary, *args, check=True):
    return subprocess.run([binary, *args], capture_output=True, text=True, check=check, env={**os.environ, "MOCK_PROVIDER_KEY": "mock"})


class Serving:
    def __init__(self, binary, folder):
        self.port = free_port()
        self.proc = subprocess.Popen([binary, "serve", str(folder / "enterplace.policy.yaml"), "--keys", str(folder / "enterplace.keys.yaml"), "--listen", f"127.0.0.1:{self.port}"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env={**os.environ, "MOCK_PROVIDER_KEY": "mock"})
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1)
                return
            except (urllib.error.URLError, ConnectionError):
                if self.proc.poll() is not None:
                    raise SystemExit(f"{binary} stopped at start:\n{self.proc.stdout.read()}")
                time.sleep(0.1)
        raise SystemExit(f"{binary} did not answer /healthz")

    def chat(self, key):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/chat/completions", method="POST",
                                     data=b'{"model":"model-a","messages":[{"role":"user","content":"hi"}]}',
                                     headers={"authorization": f"Bearer {key}", "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=10)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    old, new = (str(pathlib.Path(p).resolve()) for p in sys.argv[1:])
    print(f"old: {run(old, 'version').stdout.strip()}\nnew: {run(new, 'version').stdout.strip()}")
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    folder = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-rollback-"))
    audit = folder / "enterplace-audit.jsonl"
    (folder / "enterplace.policy.yaml").write_text(f"""version: 1
audit: {{ path: {audit} }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{provider.server_address[1]}
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [model-a]
""")
    keys = folder / "enterplace.keys.yaml"
    first = run(old, "key", "new", "first@example.com", "--team", "eng", "--keys", str(keys), "--quiet").stdout.strip()

    g = Serving(old, folder)
    check("the old version serves", all(g.chat(first) == 200 for _ in range(2)))
    g.stop()

    second = run(new, "key", "new", "second@example.com", "--team", "eng", "--keys", str(keys), "--quiet").stdout.strip()
    g = Serving(new, folder)
    check("after the upgrade, the new version serves the old key", all(g.chat(first) == 200 for _ in range(2)))
    check("the new version serves a key it issued", g.chat(second) == 200)
    g.stop()

    g = Serving(old, folder)
    check("after the rollback, the old version serves the old key", g.chat(first) == 200)
    check("after the rollback, the old version serves the key the new version issued", g.chat(second) == 200)
    g.stop()

    for name, binary in (("old", old), ("new", new)):
        v = run(binary, "audit", "verify", str(audit), check=False)
        check(f"the {name} version verifies the whole chain", v.returncode == 0, v.stdout + v.stderr)
    lines = audit.read_text().splitlines()
    usage = sum('"event":"usage"' in l for l in lines)
    check("every request left a usage record across the three runs", usage == 7, f"{usage} usage records, expected 7")
    provider.shutdown()
    print("\nall passed" if not FAILED else f"\nFAILED: {', '.join(FAILED)}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
