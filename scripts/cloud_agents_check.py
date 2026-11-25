"""Codex and Claude Code on Bedrock and Vertex AI through a local Enterplace: the check behind
docs/src/content/docs/integrations/codex-on-bedrock.mdx and claude-code-on-bedrock-and-vertex.mdx.

Usage:
  python3 scripts/cloud_agents_check.py [enterplace binary] [name ...]

Starts one mock of the cloud endpoints (standard library): Bedrock's OpenAI-compatible Responses endpoint,
ConverseStream and InvokeModel (AWS event stream framing), and Vertex AI's rawPredict for Claude. Writes a policy
with a provider of each kind pointed at the mock, runs `enterplace serve`, then runs the installed `codex exec` and
`claude -p` against it, each with a config folder of its own. A run passes when the tool prints the mock's answer:
the tool's real request went through Enterplace and the cloud's answer came back in the tool's own format.

Runs, by name: codex-responses, codex-converse, claude-bedrock, claude-vertex, claude-bedrock-native,
claude-vertex-native. With no names, all of them. Exits 1 when any fails, and prints why.
Needs `codex` and `claude` on the PATH. No cloud account, no provider key. Not part of scripts/ci.sh.
"""
import base64, hashlib, http.server, json, os, pathlib, shutil, socket, struct, subprocess, sys, tempfile, threading, time, urllib.request, zlib

KEY = "enterplace_cloud_agents_check_0123456789abcdef"
ANSWER = "hello from the mock"
SEEN = []


def frame(event, payload):
    """One AWS event stream message: prelude, headers, payload, each part with its CRC32."""
    headers = b"".join(bytes([len(n)]) + n + b"\x07" + struct.pack(">H", len(v)) + v for n, v in
                       [(b":event-type", event.encode()), (b":content-type", b"application/json"), (b":message-type", b"event")])
    body = json.dumps(payload).encode()
    prelude = struct.pack(">II", 16 + len(headers) + len(body), len(headers))
    message = prelude + struct.pack(">I", zlib.crc32(prelude)) + headers + body
    return message + struct.pack(">I", zlib.crc32(message))


def message(model):
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": [{"type": "text", "text": ANSWER}],
            "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 3, "output_tokens": 3}}


def message_events(model):
    """Anthropic's streamed events for one text answer."""
    start = {**message(model), "content": [], "stop_reason": None, "usage": {"input_tokens": 3, "output_tokens": 0}}
    return [{"type": "message_start", "message": start},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": ANSWER}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 3}},
            {"type": "message_stop"}]


def responses_events(model):
    """OpenAI's Responses stream for one text answer."""
    item = {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": ANSWER, "annotations": []}]}
    response = {"id": "resp_1", "object": "response", "created_at": 1, "model": model, "status": "in_progress", "output": []}
    done = {**response, "status": "completed", "output": [item],
            "usage": {"input_tokens": 3, "output_tokens": 3, "total_tokens": 6,
                      "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}
    events = [{"type": "response.created", "response": response},
              {"type": "response.output_item.added", "output_index": 0, "item": {**item, "status": "in_progress", "content": []}},
              {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": ANSWER},
              {"type": "response.output_item.done", "output_index": 0, "item": item},
              {"type": "response.completed", "response": done}]
    return [{**e, "sequence_number": n} for n, e in enumerate(events)]


class Cloud(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or b"{}")
        path = self.path.split("?")[0]
        SEEN.append((path, body))
        sse = lambda events: "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()
        if path.endswith("/openai/v1/responses"):
            return self.send("text/event-stream", sse(responses_events(body.get("model", ""))))
        if path.endswith("/converse-stream"):
            return self.send("application/vnd.amazon.eventstream", b"".join([
                frame("messageStart", {"role": "assistant"}),
                frame("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": ANSWER}}),
                frame("contentBlockStop", {"contentBlockIndex": 0}),
                frame("messageStop", {"stopReason": "end_turn"}),
                frame("metadata", {"usage": {"inputTokens": 3, "outputTokens": 3, "totalTokens": 6}, "metrics": {"latencyMs": 1}})]))
        if path.endswith("/invoke-with-response-stream"):
            return self.send("application/vnd.amazon.eventstream", b"".join(
                frame("chunk", {"bytes": base64.b64encode(json.dumps(e).encode()).decode()}) for e in message_events("claude")))
        if path.endswith("/count-tokens"):
            return self.send("application/json", json.dumps({"inputTokens": 5}).encode())
        if path.endswith("count-tokens:rawPredict"):
            return self.send("application/json", json.dumps({"input_tokens": 5}).encode())
        if path.endswith(":streamRawPredict"):
            return self.send("text/event-stream", sse(message_events("claude")))
        if path.endswith("/invoke") or path.endswith(":rawPredict"):
            return self.send("application/json", json.dumps(message("claude")).encode())
        self.send("application/json", json.dumps({"message": f"the mock has no {path}"}).encode(), 404)

    def do_GET(self):
        self.send("application/json", b"{}", 404)

    def send(self, kind, data, status=200):
        self.send_response(status)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def policy(port):
    return f"""version: 1
providers:
  - name: bedrock-openai
    kind: openai
    url: http://127.0.0.1:{port}/openai/v1
    allow_private: true
    key_env: BEDROCK_API_KEY
    models: [us.openai.gpt-5.6-sol]
  - name: bedrock-converse
    kind: bedrock_converse
    region: us-east-1
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [nova-pro]
    model_ids:
      nova-pro: amazon.nova-pro-v1:0
  - name: bedrock
    kind: bedrock
    region: us-east-1
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [claude-sonnet-4-5, claude-haiku-4-5]
    model_ids:
      claude-sonnet-4-5: us.anthropic.claude-sonnet-4-5-20250929-v1:0
      claude-haiku-4-5: us.anthropic.claude-haiku-4-5-20251001-v1:0
  - name: claude-vertex
    kind: vertex_anthropic
    url: http://127.0.0.1:{port}/v1/projects/my-project/locations/us-east5/publishers/anthropic
    allow_private: true
    key_env: VERTEX_ACCESS_TOKEN
    models: ["claude-sonnet-4-5@20250929", "claude-haiku-4-5@20251001"]
rules:
  - name: developers
    principals: {{ team: developers }}
    models: [us.openai.gpt-5.6-sol, nova-pro, claude-sonnet-4-5, claude-haiku-4-5, "claude-sonnet-4-5@20250929", "claude-haiku-4-5@20251001"]
    passthrough:
      - {{ provider: bedrock, paths: [/model] }}
      - {{ provider: claude-vertex, paths: [/v1/projects] }}
"""


def codex(folder, base, model, features=""):
    home = pathlib.Path(tempfile.mkdtemp(prefix="codex-home-", dir=folder))
    (home / "config.toml").write_text(f"""model = "{model}"
model_provider = "enterplace"
web_search = "disabled"
{features}
[model_providers.enterplace]
name = "Enterplace"
base_url = "{base}/v1"
env_key = "ENTERPLACE_KEY"
wire_api = "responses"
stream_max_retries = 0
request_max_retries = 0
""")
    return ["codex", "exec", "--skip-git-repo-check", "Say hello."], {"CODEX_HOME": str(home), "ENTERPLACE_KEY": KEY}


def claude(folder, env):
    home = pathlib.Path(tempfile.mkdtemp(prefix="claude-home-", dir=folder))
    quiet = {"CLAUDE_CONFIG_DIR": str(home), "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"}
    return ["claude", "-p", "Say hello."], {**quiet, **env}


def runs(folder, base):
    sonnet, haiku = "us.anthropic.claude-sonnet-4-5-20250929-v1:0", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    return {
        "codex-responses": codex(folder, base, "us.openai.gpt-5.6-sol"),
        "codex-converse": codex(folder, base, "nova-pro", "\n[features]\nmulti_agent = false\n"),
        "claude-bedrock": claude(folder, {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": KEY, "ANTHROPIC_MODEL": "claude-sonnet-4-5",
                                          "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-haiku-4-5"}),
        "claude-vertex": claude(folder, {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": KEY, "ANTHROPIC_MODEL": "claude-sonnet-4-5@20250929",
                                         "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-haiku-4-5@20251001"}),
        "claude-bedrock-native": claude(folder, {"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_BEDROCK_BASE_URL": f"{base}/bedrock",
                                                 "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1", "ANTHROPIC_AUTH_TOKEN": KEY, "AWS_REGION": "us-east-1",
                                                 "ANTHROPIC_MODEL": sonnet, "ANTHROPIC_DEFAULT_HAIKU_MODEL": haiku,
                                                 # Two Bedrock providers in this policy, so the request names one.
                                                 "ANTHROPIC_CUSTOM_HEADERS": "x-enterplace-provider: bedrock"}),
        "claude-vertex-native": claude(folder, {"CLAUDE_CODE_USE_VERTEX": "1", "ANTHROPIC_VERTEX_BASE_URL": f"{base}/vertex/v1",
                                                "ANTHROPIC_VERTEX_PROJECT_ID": "my-project", "CLOUD_ML_REGION": "us-east5",
                                                "CLAUDE_CODE_SKIP_VERTEX_AUTH": "1", "ANTHROPIC_AUTH_TOKEN": KEY,
                                                "ANTHROPIC_MODEL": "claude-sonnet-4-5@20250929",
                                                "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-haiku-4-5@20251001"}),
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    enterplace = str(pathlib.Path(args[0] if args else "target/release/enterplace").resolve())
    for tool in ("codex", "claude"):
        if not shutil.which(tool):
            sys.exit(f"FAIL  {tool} is not on the PATH. Install it, then run this again.")
    cloud = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Cloud)
    threading.Thread(target=cloud.serve_forever, daemon=True).start()
    folder = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-cloud-agents-"))
    (folder / "enterplace.policy.yaml").write_text(policy(cloud.server_address[1]))
    digest = hashlib.sha256(KEY.encode()).hexdigest()
    (folder / "enterplace.keys.yaml").write_text(f"keys:\n  - name: cloud.check\n    team: developers\n    sha256: {digest}\n")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    # The tools must not pick up this machine's own sign-ins or cloud settings.
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "CLAUDE", "OPENAI_", "AWS_", "CODEX_", "GOOGLE_", "CLOUD_ML"))}
    serve = subprocess.Popen([enterplace, "serve", str(folder / "enterplace.policy.yaml"), "--listen", f"127.0.0.1:{port}"],
                             stdout=open(folder / "enterplace.log", "w"), stderr=subprocess.STDOUT,
                             env={**clean, "BEDROCK_API_KEY": "mock", "VERTEX_ACCESS_TOKEN": "mock", "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                                  "AWS_SECRET_ACCESS_KEY": "mock", "AWS_EC2_METADATA_DISABLED": "true"})
    failed = 0
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{base}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        work = folder / "work"
        work.mkdir()
        every = runs(folder, base)
        for name in args[1:] or every:
            command, env = every[name]
            SEEN.clear()
            try:
                run = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL, env={**clean, **env})
                out = run.stdout + run.stderr
            except subprocess.TimeoutExpired as e:
                out = f"timed out after 90 seconds\n{(e.stdout or b'').decode(errors='replace')}{(e.stderr or b'').decode(errors='replace')}"
            paths = sorted({p for p, _ in SEEN})
            if ANSWER in out:
                print(f"ok    {name}: the cloud was sent {', '.join(paths)}")
            else:
                failed += 1
                print(f"FAIL  {name}: the tool did not print the mock's answer. The cloud was sent {', '.join(paths) or 'nothing'}.\n      "
                      + "\n      ".join(out.strip().splitlines()[-6:]))
        versions = [subprocess.run([t, "--version"], capture_output=True, text=True).stdout.strip() for t in ("codex", "claude")]
        print(f"With {versions[0]} and Claude Code {versions[1]}. Enterplace's log: {folder / 'enterplace.log'}")
    finally:
        serve.terminate()
        serve.wait(timeout=10)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
