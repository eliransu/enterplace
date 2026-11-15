#!/bin/sh
# A Claude Code status line that shows the model and what your Gantry budget has left.
#
# Claude Code runs this with session data as JSON on stdin and shows what it prints (its statusLine setting,
# https://code.claude.com/docs/en/statusline). `gantry budget status --short` asks the gateway for the budgets your
# own key counts against (GET /v1/gantry/me), with the key in GANTRY_KEY or the one `gantry login` saved.
#
# Install: copy to ~/.claude/gantry-statusline.sh, make it executable, and add to ~/.claude/settings.json:
#   { "statusLine": { "type": "command", "command": "~/.claude/gantry-statusline.sh", "refreshInterval": 60 } }
input=$(cat)
model=$(printf '%s' "$input" | jq -r '.model.display_name // "Claude"' 2>/dev/null)
budget=$(gantry budget status --short 2>/dev/null) || budget="budget unknown"
printf '[%s] Gantry: %s\n' "${model:-Claude}" "$budget"
