"""The live provider matrix: every route Gantry serves, run through a real `gantry serve` against each provider kind.

Usage:
  python3 scripts/live_matrix.py [--gantry target/release/gantry] [--out live-matrix.json]   real providers
  python3 scripts/live_matrix.py --mock                                                     a local mock of each API
  python3 scripts/live_matrix.py --selftest                                                 both checks CI runs

Each provider runs only when its GANTRY_LIVE_* variables are set (see PROVIDERS), and every one of its cells says
"skipped" with the variable that is missing otherwise. Each provider gets its own `gantry serve`, policy, key and audit
log, and the audit chain is verified with `gantry audit verify` at the end.

Spend: the cheapest models, prompts of a few words, max_tokens 16 (64 for a tool call), and a cap on the tokens of the
whole run, GANTRY_LIVE_MAX_TOKENS (default 20000), counted from each answer's usage (or a fixed estimate when an
answer has none). Past the cap every remaining cell is skipped.

--mock points every provider at a mock of its own API on 127.0.0.1 (it checks that the provider key, never the Gantry
key, arrives) and exits 1 unless every cell passes. --selftest runs --mock, then a run with no GANTRY_LIVE_* variable,
which must skip every cell and start no gateway. A live run exits 1 when any cell fails.

The matrix is written as JSON (--out) and as a Markdown table on stdout and in $GITHUB_STEP_SUMMARY. Standard library
only, plus `openssl` to sign the Vertex AI service account token.
"""
import argparse, base64, datetime, http.server, io, json, math, os, pathlib, re, shutil, socket, struct, subprocess, sys
import tempfile, threading, time, urllib.error, urllib.parse, urllib.request, wave, zlib

ROUTES = ["chat", "chat_stream", "messages", "messages_stream", "tool_calls", "responses", "embeddings", "images",
          "audio_speech", "audio_transcription", "moderations", "count_tokens", "passthrough"]
# Every provider serves these five: natively, or translated (accept_chat, accept_messages).
COMMON = ["chat", "chat_stream", "messages", "messages_stream", "tool_calls"]
MOCK_KEY = "mock-provider-key"


def providers(env):
    """Each provider kind: the variables it needs, its policy entry, the routes it serves and their models."""
    model = lambda pid, role, default: env.get(f"GANTRY_LIVE_{pid.upper()}_{role.upper()}_MODEL", default)
    project = env.get("GANTRY_LIVE_VERTEX_PROJECT", "")
    region = env.get("GANTRY_LIVE_VERTEX_REGION", "us-central1")
    claude_region = env.get("GANTRY_LIVE_VERTEX_CLAUDE_REGION", "us-east5")
    vertex = lambda r, publisher: f"https://{r}-aiplatform.googleapis.com/v1/projects/{project}/locations/{r}/publishers/{publisher}"
    azure_model = model("azure", "chat", "gpt-4.1-nano")
    bedrock_id = env.get("GANTRY_LIVE_BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
    return [
        dict(id="openai", label="OpenAI", need=["GANTRY_LIVE_OPENAI_KEY"], native="chat",
             fields={"kind": "openai", "key_env": "GANTRY_LIVE_OPENAI_KEY"}, url="https://api.openai.com", mock="",
             models={"chat": model("openai", "chat", "gpt-4.1-nano"),
                     "embeddings": model("openai", "embeddings", "text-embedding-3-small"),
                     "images": model("openai", "images", "gpt-image-1-mini"),
                     "audio_speech": model("openai", "audio_speech", "gpt-4o-mini-tts"),
                     "audio_transcription": model("openai", "audio_transcription", "gpt-4o-mini-transcribe"),
                     "moderations": model("openai", "moderations", "omni-moderation-latest")},
             routes=COMMON + ["responses", "embeddings", "images", "audio_speech", "audio_transcription", "moderations",
                              "passthrough"], passthrough="/v1/models"),
        dict(id="anthropic", label="Anthropic", need=["GANTRY_LIVE_ANTHROPIC_KEY"], native="messages",
             fields={"kind": "anthropic", "key_env": "GANTRY_LIVE_ANTHROPIC_KEY"}, url="https://api.anthropic.com", mock="",
             models={"chat": model("anthropic", "chat", "claude-haiku-4-5")},
             routes=COMMON + ["count_tokens", "passthrough"], passthrough="/v1/models"),
        dict(id="azure", label="Azure OpenAI", need=["GANTRY_LIVE_AZURE_KEY", "GANTRY_LIVE_AZURE_URL", "GANTRY_LIVE_AZURE_DEPLOYMENT"],
             native="chat", url=env.get("GANTRY_LIVE_AZURE_URL", ""), mock="",
             fields={"kind": "azure", "key_env": "GANTRY_LIVE_AZURE_KEY",
                     "api_version": env.get("GANTRY_LIVE_AZURE_API_VERSION", "2024-10-21"),
                     "deployments": {azure_model: env.get("GANTRY_LIVE_AZURE_DEPLOYMENT", "")}},
             models={"chat": azure_model}, routes=COMMON),
        dict(id="bedrock", label="Amazon Bedrock", need=["GANTRY_LIVE_AWS_ACCESS_KEY_ID", "GANTRY_LIVE_AWS_SECRET_ACCESS_KEY"],
             native="messages", url="", mock="",
             fields={"kind": "bedrock", "region": env.get("GANTRY_LIVE_BEDROCK_REGION", "us-east-1"),
                     "model_ids": {"claude-haiku-bedrock": bedrock_id}},
             models={"chat": "claude-haiku-bedrock"}, routes=COMMON),
        dict(id="gemini", label="Gemini", need=["GANTRY_LIVE_GEMINI_KEY"], native="chat",
             fields={"kind": "gemini", "key_env": "GANTRY_LIVE_GEMINI_KEY"},
             # No path, so the passthrough path is the API's own /v1beta/... as Google documents it.
             url="https://generativelanguage.googleapis.com", mock="",
             models={"chat": model("gemini", "chat", "gemini-2.5-flash-lite")},
             routes=COMMON + ["passthrough"], passthrough="/v1beta/models"),
        dict(id="vertex", label="Vertex AI (Gemini)", need=["GANTRY_LIVE_VERTEX_TOKEN", "GANTRY_LIVE_VERTEX_PROJECT"],
             native="chat", fields={"kind": "vertex", "key_env": "GANTRY_LIVE_VERTEX_TOKEN"}, url=vertex(region, "google"),
             mock="/v1/projects/p/locations/us-central1/publishers/google",
             models={"chat": model("vertex", "chat", "gemini-2.5-flash-lite")}, routes=COMMON),
        dict(id="vertex_anthropic", label="Vertex AI (Claude)", need=["GANTRY_LIVE_VERTEX_TOKEN", "GANTRY_LIVE_VERTEX_PROJECT"],
             native="messages", fields={"kind": "vertex_anthropic", "key_env": "GANTRY_LIVE_VERTEX_TOKEN"},
             url=vertex(claude_region, "anthropic"), mock="/v1/projects/p/locations/us-east5/publishers/anthropic",
             models={"chat": model("vertex_anthropic", "chat", "claude-haiku-4-5@20251001")}, routes=COMMON),
        dict(id="groq", label="Groq (preset)", need=["GANTRY_LIVE_GROQ_KEY"], native="chat",
             fields={"preset": "groq", "key_env": "GANTRY_LIVE_GROQ_KEY"}, url="", mock="/openai/v1",
             models={"chat": model("groq", "chat", "llama-3.1-8b-instant"),
                     "audio_transcription": model("groq", "audio_transcription", "whisper-large-v3-turbo")},
             routes=COMMON + ["audio_transcription", "passthrough"], passthrough="/v1/models"),
        dict(id="mistral", label="Mistral (preset)", need=["GANTRY_LIVE_MISTRAL_KEY"], native="chat",
             fields={"preset": "mistral", "key_env": "GANTRY_LIVE_MISTRAL_KEY"}, url="", mock="/v1",
             models={"chat": model("mistral", "chat", "mistral-small-latest"),
                     "embeddings": model("mistral", "embeddings", "mistral-embed")},
             routes=COMMON + ["embeddings", "passthrough"], passthrough="/v1/models"),
    ]


def translated(provider, route):
    if provider["native"] == "chat":
        return route in ("messages", "messages_stream")
    return route in ("chat", "chat_stream")


def policy(provider, mock_url):
    """The policy for one provider. JSON is YAML, so every value is written as JSON."""
    entry = {"name": provider["id"], **provider["fields"]}
    if mock_url is not None:
        entry["url"] = mock_url + provider["mock"]
        entry["allow_private"] = True
    elif provider["url"]:
        entry["url"] = provider["url"]
    entry["models"] = sorted(set(provider["models"].values()))
    entry["accept_messages" if provider["native"] == "chat" else "accept_chat"] = True
    rule = {"name": "live", "principals": {"any": True}, "models": ["*"]}
    if "passthrough" in provider["routes"]:
        rule["passthrough"] = [{"provider": provider["id"], "paths": [provider["passthrough"]]}]
    lines = ["version: 1", "providers:", "  - " + "\n    ".join(f"{k}: {json.dumps(v)}" for k, v in entry.items()),
             "rules:", "  - " + "\n    ".join(f"{k}: {json.dumps(v)}" for k, v in rule.items())]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------------------------------
# Requests, one per route. Each returns (passed, detail, tokens used).

PROMPT = "Reply with the word OK."
WEATHER = {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}


def tone_wav():
    """Half a second of a 440 Hz tone: an audio file for the transcription route that needs no fixture."""
    out = io.BytesIO()
    with wave.open(out, "wb") as w:
        w.setnchannels(1), w.setsampwidth(2), w.setframerate(16000)
        w.writeframes(b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / 16000))) for i in range(8000)))
    return out.getvalue()


def call(gateway, method, path, body=None, headers=None, raw=None):
    headers = {"authorization": f"Bearer {gateway['key']}", **(headers or {})}
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    if body is not None:
        headers.setdefault("content-type", "application/json")
    request = urllib.request.Request(gateway["url"] + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=90) as answer:
            return answer.status, dict(answer.headers), answer.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def parse(data):
    try:
        return json.loads(data)
    except ValueError:
        return None


def usage_tokens(usage, default):
    if not isinstance(usage, dict):
        return default
    total = usage.get("total_tokens") or ((usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
                                           + (usage.get("completion_tokens") or usage.get("output_tokens") or 0))
    return total or default


def stream_tokens(text):
    """Tokens in a stream's usage events, when it has any: OpenAI's last chunk, Anthropic's start and delta."""
    total = 0
    for line in text.splitlines():
        event = parse(line[5:].strip()) if line.startswith("data:") else None
        if isinstance(event, dict):
            total += usage_tokens(event.get("usage"), 0) + usage_tokens((event.get("message") or {}).get("usage"), 0)
    return total or 50


def run_route(route, provider, gateway):
    m = provider["models"].get(route, provider["models"]["chat"])
    chat = {"model": m, "messages": [{"role": "user", "content": PROMPT}], "max_tokens": 16}
    anthropic = {"anthropic-version": "2023-06-01"}
    if route == "tool_calls":
        ask = [{"role": "user", "content": "What is the weather in Paris? Use the tool."}]
        if provider["native"] == "chat":
            route, body = "chat", {"model": m, "messages": ask, "max_tokens": 64, "tool_choice": "required",
                                   "tools": [{"type": "function", "function": {"name": "get_weather", "description": "The weather in a city", "parameters": WEATHER}}]}
        else:
            route, body = "messages", {"model": m, "messages": ask, "max_tokens": 64, "tool_choice": {"type": "any"},
                                       "tools": [{"name": "get_weather", "description": "The weather in a city", "input_schema": WEATHER}]}
        status, headers, data = call(gateway, "POST", "/v1/chat/completions" if route == "chat" else "/v1/messages", body,
                                     None if route == "chat" else anthropic)
        answer = parse(data) or {}
        if route == "chat":
            calls = ((answer.get("choices") or [{}])[0].get("message") or {}).get("tool_calls") or []
        else:
            calls = [b for b in answer.get("content") or [] if b.get("type") == "tool_use"]
        return status == 200 and bool(calls), describe(status, headers, data, f"{len(calls)} tool call(s)"), usage_tokens(answer.get("usage"), 100)
    if route in ("chat", "chat_stream"):
        status, headers, data = call(gateway, "POST", "/v1/chat/completions", {**chat, "stream": route == "chat_stream"})
        if route == "chat":
            answer = parse(data) or {}
            ok = bool(((answer.get("choices") or [{}])[0]).get("message"))
            return status == 200 and ok, describe(status, headers, data, "chat.completion"), usage_tokens(answer.get("usage"), 50)
        text = data.decode(errors="replace")
        ok = "data: [DONE]" in text and '"chat.completion.chunk"' in text
        return status == 200 and ok, describe(status, headers, data, "chunks ending in [DONE]"), stream_tokens(text)
    if route in ("messages", "messages_stream"):
        status, headers, data = call(gateway, "POST", "/v1/messages", {**chat, "stream": route == "messages_stream"}, anthropic)
        if route == "messages":
            answer = parse(data) or {}
            return status == 200 and answer.get("type") == "message", describe(status, headers, data, "message"), usage_tokens(answer.get("usage"), 50)
        text = data.decode(errors="replace")
        return status == 200 and "event: message_stop" in text, describe(status, headers, data, "events ending in message_stop"), stream_tokens(text)
    if route == "responses":
        status, headers, data = call(gateway, "POST", "/v1/responses", {"model": m, "input": PROMPT, "max_output_tokens": 16})
        answer = parse(data) or {}
        return status == 200 and answer.get("object") == "response", describe(status, headers, data, "response"), usage_tokens(answer.get("usage"), 50)
    if route == "embeddings":
        status, headers, data = call(gateway, "POST", "/v1/embeddings", {"model": m, "input": "OK"})
        answer = parse(data) or {}
        ok = isinstance(((answer.get("data") or [{}])[0]).get("embedding"), list)
        return status == 200 and ok, describe(status, headers, data, "embedding"), usage_tokens(answer.get("usage"), 10)
    if route == "images":
        status, headers, data = call(gateway, "POST", "/v1/images/generations",
                                     {"model": m, "prompt": "a small red dot", "size": "1024x1024", "quality": "low", "n": 1})
        answer = parse(data) or {}
        image = (answer.get("data") or [{}])[0]
        return status == 200 and bool(image.get("b64_json") or image.get("url")), describe(status, headers, data, "one image"), usage_tokens(answer.get("usage"), 500)
    if route == "audio_speech":
        status, headers, data = call(gateway, "POST", "/v1/audio/speech", {"model": m, "input": "OK", "voice": "alloy", "response_format": "wav"})
        return status == 200 and len(data) > 100, describe(status, headers, data, f"{len(data)} bytes of audio"), 20
    if route == "audio_transcription":
        boundary = "gantry-live-matrix"
        form = (f"--{boundary}\r\ncontent-disposition: form-data; name=\"model\"\r\n\r\n{m}\r\n"
                f"--{boundary}\r\ncontent-disposition: form-data; name=\"file\"; filename=\"tone.wav\"\r\ncontent-type: audio/wav\r\n\r\n").encode()
        form += tone_wav() + f"\r\n--{boundary}--\r\n".encode()
        status, headers, data = call(gateway, "POST", "/v1/audio/transcriptions", None,
                                     {"content-type": f"multipart/form-data; boundary={boundary}"}, raw=form)
        answer = parse(data) or {}
        return status == 200 and "text" in answer, describe(status, headers, data, "a transcription"), usage_tokens(answer.get("usage"), 20)
    if route == "moderations":
        status, headers, data = call(gateway, "POST", "/v1/moderations", {"model": m, "input": "OK"})
        answer = parse(data) or {}
        return status == 200 and isinstance(answer.get("results"), list), describe(status, headers, data, "moderation results"), 0
    if route == "count_tokens":
        status, headers, data = call(gateway, "POST", "/v1/messages/count_tokens", {"model": m, "messages": chat["messages"]}, anthropic)
        answer = parse(data) or {}
        return status == 200 and isinstance(answer.get("input_tokens"), int), describe(status, headers, data, "input_tokens"), 0
    if route == "passthrough":
        status, headers, data = call(gateway, "GET", f"/passthrough/{provider['id']}{provider['passthrough']}", headers=anthropic)
        return status == 200 and parse(data) is not None, describe(status, headers, data, f"GET {provider['passthrough']}"), 0
    raise ValueError(route)


def describe(status, headers, data, what):
    """A cell's detail: what was checked, or the refusal or provider error that came back, without any key."""
    if status == 200 and any(h.lower() == "x-gantry-decision" for h in headers):
        return f"200, {what}"
    if status == 200:
        return f"200 but no X-Gantry-Decision header, {what}"
    text = re.sub(r"(gantry_|sk-)[A-Za-z0-9_-]+", "<key>", data.decode(errors="replace"))
    return f"{status}: {' '.join(text.split())[:300]}"


# ---------------------------------------------------------------------------------------------------------------
# A mock of each provider API, for --mock. It answers in the provider's own shape and refuses any request that does
# not carry the provider key, or that carries anything that looks like a Gantry key.

def sse(events):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def anthropic_message(model, tools):
    content = [{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}}] if tools else [{"type": "text", "text": "OK"}]
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": content,
            "stop_reason": "tool_use" if tools else "end_turn", "stop_sequence": None, "usage": {"input_tokens": 9, "output_tokens": 2}}


def anthropic_events(model):
    return [{"type": "message_start", "message": {**anthropic_message(model, False), "content": [], "stop_reason": None, "usage": {"input_tokens": 9, "output_tokens": 0}}},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "OK"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 2}},
            {"type": "message_stop"}]


def eventstream(payload):
    """One AWS event stream message, a Bedrock `chunk` (prelude, headers, payload, two CRC32s)."""
    head = b"".join(bytes([len(n)]) + n.encode() + b"\x07" + struct.pack(">H", len(v)) + v.encode()
                    for n, v in ((":message-type", "event"), (":event-type", "chunk"), (":content-type", "application/json")))
    prelude = struct.pack(">II", 16 + len(head) + len(payload), len(head))
    message = prelude + struct.pack(">I", zlib.crc32(prelude)) + head + payload
    return message + struct.pack(">I", zlib.crc32(message))


class Mock(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, body, content_type="application/json", status=200):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        values = [v for _, v in self.headers.items()]
        if any("gantry_" in v for v in values):
            return False
        sent = {self.headers.get("authorization", ""), self.headers.get("x-api-key"), self.headers.get("api-key"), self.headers.get("x-goog-api-key")}
        return f"Bearer {MOCK_KEY}" in sent or MOCK_KEY in sent or self.headers.get("authorization", "").startswith("AWS4-HMAC-SHA256 ")

    def do_GET(self):
        if not self.authorized():
            return self.reply({"error": {"message": "mock: no provider key, or a Gantry key reached the provider"}}, status=401)
        self.reply({"object": "list", "data": [{"id": "mock-model", "object": "model"}]})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", "0")))
        if not self.authorized():
            return self.reply({"error": {"message": "mock: no provider key, or a Gantry key reached the provider"}}, status=401)
        body = parse(raw) if self.headers.get("content-type", "").startswith("application/json") else {}
        body = body if isinstance(body, dict) else {}
        path = urllib.parse.urlsplit(self.path).path
        model, tools, stream = body.get("model", "mock-model"), bool(body.get("tools")), bool(body.get("stream"))
        if path.endswith("/chat/completions"):
            if stream:
                chunk = lambda delta, finish, **extra: {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": model,
                                                       "choices": [{"index": 0, "delta": delta, "finish_reason": finish}], **extra}
                events = [chunk({"role": "assistant", "content": "OK"}, None), chunk({}, "stop")]
                if (body.get("stream_options") or {}).get("include_usage"):
                    events.append({**chunk({}, None), "choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11}})
                return self.reply("".join(f"data: {json.dumps(e)}\n\n" for e in events).encode() + b"data: [DONE]\n\n", "text/event-stream")
            message = ({"role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]} if tools else {"role": "assistant", "content": "OK"})
            return self.reply({"id": "c1", "object": "chat.completion", "created": 0, "model": model,
                               "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tools else "stop"}],
                               "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11}})
        if path.endswith("/messages/count_tokens"):
            return self.reply({"input_tokens": 9})
        if path.endswith(":streamRawPredict") or (path.endswith("/messages") and stream):
            return self.reply(sse(anthropic_events(model)), "text/event-stream")
        if path.endswith("/messages") or path.endswith(":rawPredict"):
            return self.reply(anthropic_message(model, tools))
        if path.endswith("/invoke"):
            return self.reply(anthropic_message(model, tools))
        if path.endswith("/invoke-with-response-stream"):
            frames = b"".join(eventstream(json.dumps({"bytes": base64.b64encode(json.dumps(e).encode()).decode()}).encode())
                              for e in anthropic_events(model))
            return self.reply(frames, "application/vnd.amazon.eventstream")
        if ":generateContent" in path or ":streamGenerateContent" in path:
            part = {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}} if tools else {"text": "OK"}
            answer = {"candidates": [{"content": {"role": "model", "parts": [part]}, "finishReason": "STOP", "index": 0}],
                      "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 2, "totalTokenCount": 11}, "modelVersion": "mock"}
            if ":stream" in path:
                return self.reply(f"data: {json.dumps(answer)}\n\n".encode(), "text/event-stream")
            return self.reply(answer)
        if path.endswith("/responses"):
            return self.reply({"id": "resp_1", "object": "response", "status": "completed", "model": model,
                               "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                                           "content": [{"type": "output_text", "text": "OK", "annotations": []}]}],
                               "usage": {"input_tokens": 9, "output_tokens": 2, "total_tokens": 11}})
        if path.endswith("/embeddings"):
            return self.reply({"object": "list", "model": model, "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
                               "usage": {"prompt_tokens": 1, "total_tokens": 1}})
        if path.endswith("/images/generations"):
            return self.reply({"created": 0, "data": [{"b64_json": "iVBORw0KGgo="}], "usage": {"input_tokens": 5, "output_tokens": 5, "total_tokens": 10}})
        if path.endswith("/audio/speech"):
            return self.reply(tone_wav(), "audio/wav")
        if path.endswith("/audio/transcriptions"):
            return self.reply({"text": "OK"})
        if path.endswith("/moderations"):
            return self.reply({"id": "modr-1", "model": model, "results": [{"flagged": False, "categories": {}, "category_scores": {}}]})
        self.reply({"error": {"message": f"mock: no route {path}"}}, status=404)

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def vertex_token(sa_json):
    """An hour's access token for a service account: a JWT signed with its key (openssl), exchanged at Google."""
    sa = json.loads(sa_json)
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    now = int(time.time())
    claims = {"iss": sa["client_email"], "scope": "https://www.googleapis.com/auth/cloud-platform",
              "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600}
    unsigned = b64(b'{"alg":"RS256","typ":"JWT"}') + b"." + b64(json.dumps(claims).encode())
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as key:
        key.write(sa["private_key"])
        key.flush()
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key.name], input=unsigned, capture_output=True, check=True).stdout
    form = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": (unsigned + b"." + b64(signature)).decode()})
    with urllib.request.urlopen("https://oauth2.googleapis.com/token", form.encode(), timeout=30) as answer:
        return json.load(answer)["access_token"], sa.get("project_id", "")


def start_gateway(gantry, provider, folder, env, mock_url):
    folder.mkdir()
    (folder / "gantry.policy.yaml").write_text(policy(provider, mock_url))
    keys = folder / "gantry.keys.yaml"
    made = subprocess.run([gantry, "key", "new", "live-matrix", "--team", "ci", "--keys", str(keys), "--quiet"], capture_output=True, text=True)
    key = re.search(r"gantry_[0-9a-f]{64}", made.stdout)
    if not key:
        return None, f"gantry key new failed: {made.stdout} {made.stderr}"
    port = free_port()
    log = open(folder / "serve.log", "w")
    process = subprocess.Popen([gantry, "serve", str(folder / "gantry.policy.yaml"), "--keys", str(keys), "--listen", f"127.0.0.1:{port}"],
                               stdout=log, stderr=subprocess.STDOUT, env=env)
    gateway = {"url": f"http://127.0.0.1:{port}", "key": key.group(0), "process": process, "log": log, "folder": folder}
    for _ in range(200):
        if process.poll() is not None:
            break
        try:
            with urllib.request.urlopen(gateway["url"] + "/healthz", timeout=1) as answer:
                if answer.status == 200:
                    return gateway, ""
        except OSError:
            time.sleep(0.1)
    stop(gateway)
    return None, "gantry serve did not start: " + " ".join((folder / "serve.log").read_text().split())[-400:]


def stop(gateway):
    if gateway["process"].poll() is None:
        gateway["process"].terminate()
        gateway["process"].wait(timeout=15)
    gateway["log"].close()


def run(gantry, env, mock):
    """Runs the matrix. env holds the GANTRY_LIVE_* variables; mock is the mock's base URL or None."""
    env = dict(env)
    if mock is not None:
        for p in providers({}):
            for name in p["need"]:
                env[name] = MOCK_KEY
        env["GANTRY_LIVE_AZURE_URL"] = "http://placeholder"
    elif env.get("GANTRY_LIVE_VERTEX_SA_JSON") and not env.get("GANTRY_LIVE_VERTEX_TOKEN"):
        env["GANTRY_LIVE_VERTEX_TOKEN"], project = vertex_token(env["GANTRY_LIVE_VERTEX_SA_JSON"])
        env.setdefault("GANTRY_LIVE_VERTEX_PROJECT", project)
    cap = int(env.get("GANTRY_LIVE_MAX_TOKENS", "20000"))
    version = subprocess.run([gantry, "version"], capture_output=True, text=True).stdout.strip()
    matrix = {"schema": 1, "mode": "mock" if mock is not None else "live", "gantry": version,
              "commit": env.get("GITHUB_SHA") or subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
              "run": f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}" if env.get("GITHUB_RUN_ID") else None,
              "started": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "token_cap": cap, "tokens": 0, "routes": ROUTES, "providers": [], "results": {r: {} for r in ROUTES}}
    work = pathlib.Path(tempfile.mkdtemp(prefix="gantry-live-matrix-"))
    try:
        for provider in providers(env):
            missing = [name for name in provider["need"] if not env.get(name)]
            entry = {"id": provider["id"], "label": provider["label"], "model": provider["models"]["chat"], "ran": False}
            matrix["providers"].append(entry)
            cell = lambda route, status, detail: matrix["results"][route].__setitem__(provider["id"], {
                "status": status, "detail": detail, "translated": translated(provider, route) and route != "tool_calls",
                "model": provider["models"].get(route, provider["models"]["chat"])})
            if missing:
                entry["skipped"] = f"not set: {', '.join(missing)}" + (" (GANTRY_LIVE_VERTEX_SA_JSON sets both)" if "VERTEX" in missing[0] else "")
                for route in provider["routes"]:
                    cell(route, "skipped", entry["skipped"])
                print(f"skipped {provider['label']}: {entry['skipped']}", file=sys.stderr)
                continue
            gateway_env = {**os.environ, **env}
            if provider["id"] == "bedrock":
                gateway_env["AWS_ACCESS_KEY_ID"] = env["GANTRY_LIVE_AWS_ACCESS_KEY_ID"]
                gateway_env["AWS_SECRET_ACCESS_KEY"] = env["GANTRY_LIVE_AWS_SECRET_ACCESS_KEY"]
                gateway_env.pop("AWS_SESSION_TOKEN", None)
            gateway, error = start_gateway(gantry, provider, work / provider["id"], gateway_env, mock)
            if not gateway:
                for route in provider["routes"]:
                    cell(route, "fail", error)
                continue
            entry["ran"] = True
            try:
                for route in provider["routes"]:
                    if matrix["tokens"] >= cap:
                        cell(route, "skipped", f"token cap of {cap} reached")
                        continue
                    try:
                        passed, detail, tokens = run_route(route, provider, gateway)
                    except OSError as error:
                        passed, detail, tokens = False, f"no answer: {error}", 0
                    matrix["tokens"] += tokens
                    cell(route, "pass" if passed else "fail", detail)
                    print(f"{'pass' if passed else 'FAIL'}  {provider['id']:<17} {route:<20} {detail[:120]}", file=sys.stderr)
            finally:
                stop(gateway)
            verify = subprocess.run([gantry, "audit", "verify", str(gateway["folder"] / "gantry-audit.jsonl")], capture_output=True, text=True)
            # The temporary path means nothing after the run: keep what was verified.
            entry["audit"] = {"verified": verify.returncode == 0, "detail": " ".join((verify.stdout + verify.stderr).split()).split(".jsonl: ")[-1][:300]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return matrix


def markdown(matrix):
    ids = [p["id"] for p in matrix["providers"]]
    mark = {"pass": "pass", "fail": "**fail**", "skipped": "skipped"}
    lines = [f"### Live provider matrix ({matrix['mode']})", "",
             f"{matrix['gantry']}, commit `{matrix['commit'][:12]}`, {matrix['started']}, {matrix['tokens']} of {matrix['token_cap']} tokens.", "",
             "| Route | " + " | ".join(p["label"] for p in matrix["providers"]) + " |", "|---|" + "---|" * len(ids)]
    for route in matrix["routes"]:
        cells = [matrix["results"][route].get(i) for i in ids]
        lines.append(f"| `{route}` | " + " | ".join(mark[c["status"]] + (" (translated)" if c["translated"] else "") if c else "n/a" for c in cells) + " |")
    details = [f"- {p['label']}: {p['skipped']}" for p in matrix["providers"] if p.get("skipped")]
    details += [f"- {matrix['results'][r][i]['status']} {i} `{r}`: {matrix['results'][r][i]['detail']}"
                for r in matrix["routes"] for i in ids if matrix["results"][r].get(i, {}).get("status") == "fail"]
    details += [f"- audit chain {p['id']}: {p['audit']['detail']}" for p in matrix["providers"] if p.get("audit")]
    return "\n".join(lines + ([""] + details if details else [])) + "\n"


def cells(matrix):
    return [c for route in matrix["results"].values() for c in route.values()]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--gantry", default="target/release/gantry")
    parser.add_argument("--out", default="live-matrix.json")
    parser.add_argument("--mock", action="store_true", help="point every provider at a local mock of its API")
    parser.add_argument("--selftest", action="store_true", help="--mock must pass every cell; no keys must skip every cell")
    args = parser.parse_args()
    gantry = str(pathlib.Path(args.gantry).resolve())
    live_env = {k: v for k, v in os.environ.items() if k.startswith(("GANTRY_LIVE_", "GITHUB_"))}

    mock_url = None
    if args.mock or args.selftest:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        mock_url = f"http://127.0.0.1:{server.server_address[1]}"

    if args.selftest:
        mocked = run(gantry, live_env, mock_url)
        bad = [f"{r} {i}: {c['detail']}" for r, row in mocked["results"].items() for i, c in row.items() if c["status"] != "pass"]
        bad += [f"audit {p['id']}: {p['audit']['detail']}" for p in mocked["providers"] if not p["audit"]["verified"]]
        print(markdown(mocked))
        keyless = run(gantry, {k: v for k, v in live_env.items() if k.startswith("GITHUB_")}, None)
        bad += [f"{r} {i} ran without keys" for r, row in keyless["results"].items() for i, c in row.items() if c["status"] != "skipped"]
        bad += [f"{p['id']} started a gateway without keys" for p in keyless["providers"] if p["ran"]]
        print(markdown(keyless))
        if bad:
            sys.exit("FAIL\n" + "\n".join(bad))
        print(f"PASS  {len(cells(mocked))} cells passed against the mocks, {len(cells(keyless))} skipped without keys")
        return

    matrix = run(gantry, live_env, mock_url)
    pathlib.Path(args.out).write_text(json.dumps(matrix, indent=2) + "\n")
    table = markdown(matrix)
    print(table)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(table)
    failed = [c for c in cells(matrix) if c["status"] == "fail"]
    if failed or (args.mock and any(c["status"] != "pass" for c in cells(matrix))):
        sys.exit(f"{len(failed)} cell(s) failed")


if __name__ == "__main__":
    main()
