---
name: setup
description: Connect Claude Code to your organization's Enterplace AI gateway, with your name on every call. Use when the user asks to route Claude Code through Enterplace, set up Enterplace, or check that the gateway is in use.
---

1. Ask for the gateway address and the person token the organization's admin handed out (it starts with
   `enterplace_u_`). If the user has neither, say that the admin hands them out from the console's Coding agents page,
   and stop. Do not install a gateway yourself.
2. Check the gateway: `curl -fsS <gateway>/healthz`. If it fails, say the address is wrong or unreachable from this
   machine, and stop.
3. Say what will change and ask before editing. Then add two keys under `env` in `~/.claude/settings.json`, keeping
   every other key:
   `"ANTHROPIC_BASE_URL": "<gateway>"` and `"ANTHROPIC_CUSTOM_HEADERS": "x-enterplace-user: <person token>"`.
   If the file is not valid JSON, stop and say so.
4. Check that `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are unset in the shell and in that file. With either set,
   Claude Code stops using the Claude subscription login. The login passes through Enterplace to Anthropic unchanged;
   the person token only names the user.
5. Tell the user to restart Claude Code and send one prompt. The admin sees it under their name in the console
   (Requests).
6. Say that the Code tab of the Claude desktop app sets `ANTHROPIC_BASE_URL` itself, so this works in the terminal and
   the VS Code extension only.
7. To undo: remove those two `env` keys and restart Claude Code.

Full guide: https://docs.enterplace.dev/integrations/claude-code/
