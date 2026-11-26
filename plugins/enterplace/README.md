# Enterplace plugin for Claude Code

One skill, `/enterplace:setup`, that connects Claude Code to your organization's Enterplace AI gateway, with your
name on every call.

## What it changes

The skill asks first, then adds two keys to the `env` block of `~/.claude/settings.json`:

```json
{ "env": {
  "ANTHROPIC_BASE_URL": "https://ai-gateway.your-company.com",
  "ANTHROPIC_CUSTOM_HEADERS": "x-enterplace-user: enterplace_u_..."
} }
```

From then on Claude Code sends its model requests to your organization's gateway, which applies its rules, budgets and
guardrails and forwards them to Anthropic. Your Claude subscription login passes through unchanged and is never
stored; the person token only names you. The plugin installs no hook, no MCP server and no background process. To undo
it, remove those two keys.

## Use

```
/plugin marketplace add eliransu/enterplace
/plugin install enterplace@enterplace
/enterplace:setup
```

Your admin gives you the gateway address and your person token. To run the gateway for your organization, follow
https://docs.enterplace.dev/getting-started/quickstart/.
Guide: https://docs.enterplace.dev/integrations/claude-code/
