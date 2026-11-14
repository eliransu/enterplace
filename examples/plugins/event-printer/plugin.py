#!/usr/bin/env python3
"""A reference plugin for Gantry's events guardrail (contract v2). Standard library only.

It prints every event it is sent, one line each, and blocks any tool call (the model's or an MCP one) whose tool is
named in --block. Point a `type: events` guardrail at it:

    python3 plugin.py --port 9200 --block delete_file

    guardrails:
      - name: watcher
        type: events
        url: http://127.0.0.1:9200/events
        on_failure: fail_closed

With PLUGIN_SECRET set (the guardrail's secret_env names the same secret on Gantry's side) it refuses a delivery whose
Standard Webhooks signature does not check out. The contract: docs/src/content/docs/governance/plugin-events.mdx.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BLOCKED = set()
SECRET = os.environ.get("PLUGIN_SECRET", "")
CALLS = ("tool_call", "mcp_tool_call")


def signed(headers, body):
    """Standard Webhooks: v1,<base64 HMAC-SHA256 of "id.timestamp.body">, and a timestamp at most five minutes old."""
    msg_id = headers.get("webhook-id", "")
    stamp = headers.get("webhook-timestamp", "")
    if not stamp.isdigit() or abs(time.time() - int(stamp)) > 300:
        return False
    key = base64.b64decode(SECRET[6:]) if SECRET.startswith("whsec_") else SECRET.encode()
    want = base64.b64encode(hmac.new(key, f"{msg_id}.{stamp}.".encode() + body, hashlib.sha256).digest()).decode()
    return any(hmac.compare_digest(part, f"v1,{want}") for part in headers.get("webhook-signature", "").split())


def show(envelope):
    for event in envelope["events"]:
        what = event.get("content")
        if event["kind"] in CALLS:
            what = f'{event.get("name")}({json.dumps(event.get("arguments"))})'
        elif event["kind"] == "tool_definitions":
            what = ", ".join(tool["name"] for tool in event["tools"])
        elif event["kind"] in ("tool_result", "mcp_tool_result"):
            what = f'{event.get("name")} -> {what}'
        print(
            f'{envelope["session_id"]} {envelope["turn_id"]} #{event["event_index"]} '
            f'{envelope["phase"]:<8} {event["kind"]:<18} {str(what)[:120]!r}',
            flush=True,
        )


def judge(envelope):
    findings = [
        {"kind": "blocked_tool", "event": event["event_index"], "severity": "high"}
        for event in envelope["events"]
        if event["kind"] in CALLS and event.get("name") in BLOCKED
    ]
    return {"action": "block", "findings": findings} if findings else {"action": "allow"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        if SECRET and not signed(self.headers, body):
            # Not 2xx: Gantry applies the guardrail's on_failure, which is what a forged delivery deserves.
            return self.answer(401, {"error": "bad signature"})
        sent = json.loads(body)
        # Observe mode with a batch_url sends {"contract": 2, "batch": [envelope, ...]} and reads no verdict.
        if "batch" in sent:
            for envelope in sent["batch"]:
                show(envelope)
            return self.answer(200, {})
        show(sent)
        self.answer(200, judge(sent))

    def answer(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=9200)
    parser.add_argument("--block", action="append", default=[], help="a tool to block, by name; repeat for more")
    args = parser.parse_args()
    BLOCKED.update(args.block)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"listening on http://127.0.0.1:{server.server_address[1]}/events, blocking: {sorted(BLOCKED) or 'nothing'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
