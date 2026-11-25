---
name: setup
description: Point Claude Code at a local Enterplace gateway. Use when the user asks to route Claude Code through Enterplace, set up Enterplace, or check that the gateway is in use.
---

1. Check the gateway: `curl -fsS http://127.0.0.1:8080/healthz`. If it fails, tell the user to install and start it by
   following https://docs.enterplace.dev/getting-started/quickstart/ and stop. Do not install it yourself.
2. Say what will change and ask before editing. Then add `"ANTHROPIC_BASE_URL": "http://127.0.0.1:8080"` under `env` in
   `~/.claude/settings.json`, keeping every other key. If the file is not valid JSON, stop and say so.
3. Check that `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are unset in the shell and in that file. With either set,
   Claude Code stops using the Claude subscription login. The login passes through Enterplace to Anthropic unchanged.
4. Tell the user to restart Claude Code, send one prompt, and open http://127.0.0.1:8080/console (Requests). The request
   shows under the person `unknown` until a person token is added.
5. Say that the Code tab of the Claude desktop app sets `ANTHROPIC_BASE_URL` itself, so this works in the terminal and
   the VS Code extension only.
6. To undo: remove that one `env` key and restart Claude Code.

Full guide: https://docs.enterplace.dev/integrations/claude-code/
