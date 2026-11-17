"""Captures one real Claude Code OTLP export against a local receiver. The model call goes to a mock on this machine."""
import http.server, json, os, subprocess, sys, threading, pathlib, shutil

proto = sys.argv[1]  # http/json or http/protobuf
out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
seen = []

SSE = [
    ("message_start", {"type": "message_start", "message": {"id": "msg_mock1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1200, "cache_creation_input_tokens": 300, "cache_read_input_tokens": 5000, "output_tokens": 1}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 40}}),
    ("message_stop", {"type": "message_stop"}),
]

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self): self.do_POST()
    def do_HEAD(self): self.do_POST()
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        seen.append((self.command, self.path, self.headers.get("content-type"), len(body)))
        if "/v1/metrics" in self.path or "/v1/logs" in self.path or "/v1/traces" in self.path:
            kind = self.path.rsplit("/", 1)[-1]
            i = len(list(out.glob(f"{kind}-*")))
            ext = "json" if "json" in (self.headers.get("content-type") or "") else "pb"
            (out / f"{kind}-{i}.{ext}").write_bytes(body)
            (out / f"{kind}-{i}.headers").write_text("".join(f"{k}: {v}\n" for k, v in self.headers.items() if k.lower() != "authorization") + f"authorization-present: {bool(self.headers.get('authorization'))}\n")
            self.send_response(200); self.send_header("content-type", self.headers.get("content-type") or "application/json")
            payload = b"{}" if ext == "json" else b""
            self.send_header("content-length", str(len(payload))); self.end_headers(); self.wfile.write(payload); return
        if self.path.startswith("/v1/messages") and "count_tokens" not in self.path:
            req = json.loads(body or b"{}")
            if req.get("stream"):
                data = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in SSE).encode()
                self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("request-id", "req_mock1")
                self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data); return
            msg = {"id": "msg_mock1", "type": "message", "role": "assistant", "model": req.get("model", "m"), "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 2}}
            data = json.dumps(msg).encode()
            self.send_response(200); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data); return
        data = b"{}"
        self.send_response(404); self.send_header("content-type", "application/json"); self.send_header("content-length", "2"); self.end_headers(); self.wfile.write(data)

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
home = out / "claude-config"; shutil.rmtree(home, ignore_errors=True); home.mkdir()
work = out / "work"; work.mkdir(exist_ok=True)
env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC", "OTEL"))}
env.update({
    "CLAUDE_CONFIG_DIR": str(home), "ANTHROPIC_API_KEY": "sk-ant-local-mock", "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp", "OTEL_LOGS_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": proto,
    "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{port}/otlp", "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer enterplace_watch_capture",
    "OTEL_METRIC_EXPORT_INTERVAL": "1000", "OTEL_LOGS_EXPORT_INTERVAL": "1000", "OTEL_LOG_USER_PROMPTS": "1",
    "OTEL_RESOURCE_ATTRIBUTES": "user.email=maya.cohen@example.com,department=engineering",
})
try:
    r = subprocess.run(["claude", "-p", "PROMPT-SECRET reply with the single word ok", "--model", "claude-sonnet-5-5"], cwd=work, env=env, capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL)
    print("exit", r.returncode, "stdout", r.stdout[:300], "stderr", r.stderr[:600])
except subprocess.TimeoutExpired as e:
    print("timeout", (e.stdout or b"")[:300], (e.stderr or b"")[:300])
for s in seen: print(s)
