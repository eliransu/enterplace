#!/bin/sh
# A Claude Code status line that shows the model and what your Enterplace budget has left.
#
# Claude Code runs this with session data as JSON on stdin and shows what it prints (its statusLine setting,
# https://code.claude.com/docs/en/statusline). `enterplace budget status --short` asks the gateway for the budgets your
# own key counts against (GET /v1/enterplace/me), with the key in ENTERPLACE_KEY or the one `enterplace login` saved.
#
# Install: copy to ~/.claude/enterplace-statusline.sh, make it executable, and add to ~/.claude/settings.json:
#   { "statusLine": { "type": "command", "command": "~/.claude/enterplace-statusline.sh", "refreshInterval": 60 } }
input=$(cat)
model=$(printf '%s' "$input" | jq -r '.model.display_name // "Claude"' 2>/dev/null)
budget=$(enterplace budget status --short 2>/dev/null) || budget="budget unknown"
printf '[%s] Enterplace: %s\n' "${model:-Claude}" "$budget"
