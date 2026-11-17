"""LangChain against a local Enterplace: the check behind docs/src/content/docs/integrations/langchain.mdx.

Usage:
  uv run --with langchain-openai --with langchain-anthropic python3 scripts/langchain_check.py [enterplace binary] [--js]

Starts a mock provider (OpenAI chat completions and Anthropic messages, standard library), writes a policy and a keys
file, runs `enterplace serve` on them, and drives LangChain's ChatOpenAI and ChatAnthropic through it: a plain call, a
streamed call, a tool call, a model the rule does not allow (refused with model_not_allowed) and a function tool it
does not allow (refused with tool_not_allowed). With --js it also runs scripts/langchain_check.mjs with Node, after
installing @langchain/openai and @langchain/anthropic in a temporary folder. No provider key is needed.
"""
import hashlib, http.server, json, os, pathlib, socket, subprocess, sys, tempfile, threading, time, urllib.request

KEY = "enterplace_langchain_check_0123456789abcdef"


class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or b"{}")
        tools = body.get("tools") or []
        stream = body.get("stream") is True
        if self.path.endswith("/chat/completions"):
            if tools:
                name = tools[0].get("function", {}).get("name", "")
                message = {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": name, "arguments": "{\"city\": \"Haifa\"}"}}]}
                answer = {"id": "c", "object": "chat.completion", "created": 1, "model": body["model"],
                          "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
                          "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}}
            elif stream:
                chunk = lambda delta, end: {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": body["model"],
                                            "choices": [{"index": 0, "delta": delta, "finish_reason": end}]}
                events = [chunk({"role": "assistant", "content": "hel"}, None), chunk({"content": "lo"}, "stop"),
                          {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": body["model"], "choices": [],
                           "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}}]
                return self.send("text/event-stream", "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n")
            else:
                answer = {"id": "c", "object": "chat.completion", "created": 1, "model": body["model"],
                          "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
                          "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}}
        else:
            content = [{"type": "tool_use", "id": "t1", "name": tools[0]["name"], "input": {"city": "Haifa"}}] if tools else [{"type": "text", "text": "hello"}]
            answer = {"id": "m", "type": "message", "role": "assistant", "model": body["model"], "content": content,
                      "stop_reason": "tool_use" if tools else "end_turn", "usage": {"input_tokens": 3, "output_tokens": 1}}
        self.send("application/json", json.dumps(answer))

    def send(self, kind, text):
        data = text.encode()
        self.send_response(200)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def policy(port):
    return f"""version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}/v1
    allow_private: true
    key_env: OPENAI_PROVIDER_KEY
    models: [gpt-4o-mini, gpt-4o]
  - name: anthropic
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-4-6]
rules:
  - name: apps
    principals: {{ team: apps }}
    models: [gpt-4o-mini, claude-sonnet-4-6]
    tools: [function.get_weather]
"""


def python_checks(base):
    from langchain_anthropic import ChatAnthropic
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
    import anthropic, openai

    @tool
    def get_weather(city: str) -> str:
        """The weather in a city."""
        return "sunny"

    @tool
    def run_shell(command: str) -> str:
        """Run a shell command."""
        return ""

    gpt = ChatOpenAI(model="gpt-4o-mini", base_url=f"{base}/v1", api_key=KEY)
    assert gpt.invoke("Say hello.").content == "hello"
    assert "".join(c.content for c in gpt.stream("Say hello.")) == "hello"
    call = gpt.bind_tools([get_weather]).invoke("Weather in Haifa?")
    assert call.tool_calls[0]["name"] == "get_weather", call
    claude = ChatAnthropic(model="claude-sonnet-4-6", base_url=base, api_key=KEY, max_tokens=64)
    assert claude.invoke("Say hello.").content == "hello"
    call = claude.bind_tools([get_weather]).invoke("Weather in Haifa?")
    assert call.tool_calls[0]["name"] == "get_weather", call
    for model, code in [(ChatOpenAI(model="gpt-4o", base_url=f"{base}/v1", api_key=KEY, max_retries=0), "model_not_allowed"),
                        (gpt.bind_tools([run_shell]), "tool_not_allowed")]:
        try:
            model.invoke("hi")
            sys.exit(f"FAIL  expected {code}")
        except openai.PermissionDeniedError as e:
            assert e.code == code, (e.code, e.body)
    try:
        claude.bind_tools([run_shell]).invoke("hi")
        sys.exit("FAIL  expected tool_not_allowed on messages")
    except anthropic.PermissionDeniedError as e:
        assert "tool_not_allowed" in str(e), e
    print("ok    LangChain Python: ChatOpenAI and ChatAnthropic, plain, streamed, tool calls, three refusals")


def js_checks(base):
    work = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-langchain-js-"))
    subprocess.run(["npm", "install", "--silent", "--no-audit", "--no-fund", "@langchain/openai@1", "@langchain/anthropic@1", "@langchain/core@1", "zod@3"],
                   cwd=work, check=True)
    script = pathlib.Path(__file__).resolve().parent / "langchain_check.mjs"
    (work / "check.mjs").write_text(script.read_text())
    subprocess.run(["node", "check.mjs"], cwd=work, check=True, env={**os.environ, "ENTERPLACE_URL": base, "ENTERPLACE_KEY": KEY})


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    enterplace = str(pathlib.Path(args[0] if args else "target/release/enterplace").resolve())
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    folder = pathlib.Path(tempfile.mkdtemp(prefix="enterplace-langchain-"))
    (folder / "enterplace.policy.yaml").write_text(policy(provider.server_address[1]))
    digest = hashlib.sha256(KEY.encode()).hexdigest()
    (folder / "enterplace.keys.yaml").write_text(f"keys:\n  - name: langchain.app\n    team: apps\n    sha256: {digest}\n")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    serve = subprocess.Popen([enterplace, "serve", str(folder / "enterplace.policy.yaml"), "--listen", f"127.0.0.1:{port}"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                             env={**os.environ, "OPENAI_PROVIDER_KEY": "mock", "ANTHROPIC_PROVIDER_KEY": "mock"})
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{base}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        python_checks(base)
        if "--js" in sys.argv:
            js_checks(base)
    finally:
        serve.terminate()
        serve.wait(timeout=10)


main()
