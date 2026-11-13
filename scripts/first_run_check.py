"""First run, timed: the acceptance check of package 5.3.

Usage: python3 scripts/first_run_check.py [gantry binary]   (default: target/release/gantry)
From an empty folder: `gantry init`, `gantry serve`, open the setup link it prints, make the first admin key, and
make a governed call with it. Passes when that call succeeds within 60 seconds of starting. The provider is a local
mock (the policy's URL is pointed at it), so no real provider key is needed. Standard library only.
"""
import http.server, json, os, pathlib, re, signal, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request

LIMIT = 60.0


class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", "0")))
        body = json.dumps({"id": "c", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def request(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    gantry = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/release/gantry").resolve())
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    folder = pathlib.Path(tempfile.mkdtemp(prefix="gantry-first-run-"))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    start = time.monotonic()
    step = lambda what: print(f"{time.monotonic() - start:6.2f}s  {what}")
    policy = folder / "gantry.policy.yaml"
    subprocess.run([gantry, "init", "--out", str(policy)], check=True, capture_output=True)
    step("gantry init wrote the policy")
    # Stands in for the real provider: the same policy, pointed at the local mock.
    text = policy.read_text().replace("    preset: openai\n", f"    preset: openai\n    url: http://127.0.0.1:{provider.server_address[1]}\n    allow_private: true\n")
    policy.write_text(text)

    serve = subprocess.Popen([gantry, "serve", str(policy), "--listen", f"127.0.0.1:{port}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             env={**os.environ, "OPENAI_PROVIDER_KEY": "mock"})
    try:
        link = None
        for line in serve.stdout:
            match = re.search(r"(http://\S+/console/setup/\S+)", line)
            if match:
                link = match.group(1)
                break
        if not link:
            sys.exit(f"FAIL  gantry serve printed no setup link:\n{serve.stdout.read() if serve.stdout else ''}")
        step("gantry serve printed the setup link")

        status, page = request(link)
        assert status == 200, (status, page[:300])
        origin = f"http://127.0.0.1:{port}"
        status, page = request(link, urllib.parse.urlencode({"name": "first.admin", "team": "platform"}).encode(),
                               {"origin": origin, "content-type": "application/x-www-form-urlencoded"})
        key = re.search(r"gantry_[0-9a-f]{64}", page)
        assert status == 200 and key, (status, page[:300])
        step("the setup link made the first admin key")

        body = json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]}).encode()
        for _ in range(50):
            status, answer = request(f"{origin}/v1/chat/completions", body, {"authorization": f"Bearer {key.group(0)}", "content-type": "application/json"})
            if status == 200:
                break
            time.sleep(0.1)
        took = time.monotonic() - start
        step(f"governed call answered {status}")
        ok = status == 200 and took < LIMIT
        print(f"\n{'PASS' if ok else 'FAIL'}  first governed call {took:.1f}s after starting (limit {LIMIT:.0f}s)")
        sys.exit(0 if ok else 1)
    finally:
        serve.send_signal(signal.SIGTERM)
        serve.wait(timeout=10)
        provider.shutdown()


if __name__ == "__main__":
    main()
