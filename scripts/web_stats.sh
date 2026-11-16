#!/bin/sh
# Website and docs traffic from the gantry-web D1 database (written by site/worker.js).
# Usage: scripts/web_stats.sh [days]        the standard report for the last N days (default 7)
#        scripts/web_stats.sh --sql "..."   any query on the hits table (schema: site/web-schema.sql)
set -eu
cd "$(dirname "$0")/.."
q() { npx --prefix docs wrangler d1 execute gantry-web --remote --command "$1" 2>/dev/null | sed -n '/^\[/,$p' \
  | python3 -c 'import json,sys
for r in json.load(sys.stdin)[0]["results"]: print("  " + " | ".join(str(v) for v in r.values()))'; }

if [ "${1:-}" = "--sql" ]; then q "$2"; exit; fi
days=${1:-7}
since="t >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-$days days')"
echo "Last $days days"
echo "By kind (view = browser, agent = bot or AI agent, install = install.sh, click):"
q "SELECT kind, site, count(*) n FROM hits WHERE $since GROUP BY kind, site ORDER BY n DESC"
echo "Top pages, browsers:"
q "SELECT site, path, count(*) n FROM hits WHERE $since AND kind = 'view' GROUP BY site, path ORDER BY n DESC LIMIT 15"
echo "Sources (other sites and utm_source):"
q "SELECT source, kind, count(*) n FROM hits WHERE $since AND source != '' GROUP BY source, kind ORDER BY n DESC LIMIT 15"
echo "Agents:"
q "SELECT agent, count(*) n, count(DISTINCT path) pages FROM hits WHERE $since AND agent != '' GROUP BY agent ORDER BY n DESC LIMIT 20"
echo "Clicks and copies:"
q "SELECT event, detail, path, count(*) n FROM hits WHERE $since AND kind = 'click' GROUP BY event, detail, path ORDER BY n DESC LIMIT 25"
echo "Countries, browsers:"
q "SELECT country, count(*) n FROM hits WHERE $since AND kind = 'view' GROUP BY country ORDER BY n DESC LIMIT 10"
