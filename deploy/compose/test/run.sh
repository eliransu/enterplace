#!/bin/sh
# The Docker guide as a customer follows it: in an empty folder, write docker-compose.yml, .env and the trial override
# exactly as the docs page shows them, fill in .env, start the stack, issue a key, make a governed call through the
# stand-in provider and verify the audit chain, all with the one published image.
#
# Usage: run.sh <path to gantry/docs/src/content/docs/deploy/docker.mdx>
# GANTRY_IMAGE, when set, is written into .env in place of the docs' image, as a customer pins a version.
set -eu
page=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
dir=$(mktemp -d)
cd "$dir"
echo "working in $dir, an empty folder"

# A fenced block with title="<name>", inside <Steps> or not: its fence's indent is taken off every line.
extract() {
  awk -v name="$1" '
    !inside && index($0, "title=\"" name "\"") && match($0, /^ *```/) { indent = RLENGTH - 3; inside = 1; next }
    inside && substr($0, indent + 1, 3) == "```" { exit }
    inside { print substr($0, indent + 1) }
  ' "$page"
}
extract docker-compose.yml > docker-compose.yml
# The first block of each name: the production section shows a line of .env and a monitoring override again.
extract .env > .env
extract docker-compose.override.yml > docker-compose.override.yml
for f in docker-compose.yml .env docker-compose.override.yml; do
  [ -s "$f" ] || { echo "the page has no block titled $f"; exit 1; }
done
grep -q 'image: python:3.12-alpine' docker-compose.override.yml || { echo "the first override on the page is not the trial one"; exit 1; }

# Filled in as the page says.
sed -i.bak "s/^POSTGRES_PASSWORD=\$/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i.bak "s/^GANTRY_PORT=.*/GANTRY_PORT=${GANTRY_PORT:-18080}/" .env
[ -z "${GANTRY_IMAGE:-}" ] || sed -i.bak "s|^GANTRY_IMAGE=.*|GANTRY_IMAGE=$GANTRY_IMAGE|" .env
rm -f .env.bak
chmod 600 .env
port=$(sed -n 's/^GANTRY_PORT=//p' .env)
echo "--- files"
ls -la

cleanup() {
  status=$?
  [ $status -ne 0 ] && docker compose logs || true
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$dir"
  exit $status
}
trap cleanup EXIT

docker compose up -d
url="http://127.0.0.1:$port"
i=0
until curl -fsS "$url/healthz" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 90 ] || { echo "gantry did not answer /healthz within 90 s"; exit 1; }
  sleep 1
done
echo "healthz: $(curl -fsS "$url/healthz")"

docker compose logs gantry | grep 'First run' || { echo "no first-run setup link in the log"; exit 1; }

key=$(docker compose run --rm -T gantry key new maya.cohen --team payments --policy /etc/gantry/gantry.policy.yaml --quiet | tail -n 1)
case "$key" in gantry_*) ;; *) echo "key new printed no key: $key"; exit 1 ;; esac
echo "key new: a key, from the gantry image"

i=0
while :; do
  answer=$(curl -sS -w '\n%{http_code}' "$url/v1/chat/completions" \
    -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}]}')
  code=$(echo "$answer" | tail -n 1)
  [ "$code" = 200 ] && break
  i=$((i + 1)); [ $i -lt 10 ] || { echo "governed call failed: $answer"; exit 1; }
  sleep 1
done
echo "$answer" | head -n 1 | grep -q pong || { echo "unexpected answer: $answer"; exit 1; }
echo "governed call: 200, answer from the stand-in"

# Without a key the gateway refuses: the call above went through the policy, not around it.
code=$(curl -sS -o /dev/null -w '%{http_code}' "$url/v1/chat/completions" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}]}')
[ "$code" = 401 ] || { echo "a call without a key got $code, not 401"; exit 1; }
echo "call without a key: 401"

docker compose run --rm -T gantry check /etc/gantry/gantry.policy.yaml
docker compose run --rm -T gantry audit verify /var/lib/gantry/gantry-audit.jsonl
echo "compose test passed"
