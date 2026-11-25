# Enterplace plugin for Claude Code

One skill, `/enterplace:setup`, that points Claude Code at an Enterplace gateway running on your own machine.

## What it changes

The skill asks first, then adds one key to the `env` block of `~/.claude/settings.json`:

```json
{ "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:8080" } }
```

From then on Claude Code sends its model requests to the gateway at `127.0.0.1:8080` and the gateway forwards them to
Anthropic. Your Claude subscription login passes through unchanged and is never stored. Nothing is sent anywhere else,
and the plugin installs no hook, no MCP server and no background process. To undo it, remove that key.

## Use

```
/plugin marketplace add eliransu/enterplace
/plugin install enterplace@enterplace
/enterplace:setup
```

The gateway itself is installed apart from the plugin. Follow the quickstart at
https://docs.enterplace.dev/getting-started/quickstart/, then start it with `enterplace start`.
Guide: https://docs.enterplace.dev/integrations/claude-code/
