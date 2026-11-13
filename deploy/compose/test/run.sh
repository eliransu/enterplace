#!/bin/sh
# The Compose stack end to end: start it, issue a key, make a governed call through the mock, verify the audit chain.
# Run from anywhere. Uses GANTRY_IMAGE and GANTRY_CLI_IMAGE when set (prebuilt images), else builds both.
# NO_STORE=1 runs without the policy's store section, for a gantry build that does not have the store yet.
set -eu
cd "$(dirname "$0")/.."

export POSTGRES_PASSWORD=composetest GANTRY_PORT="${GANTRY_PORT:-18080}"
policy=test/gantry.test.policy.yaml
key_flags="--policy /etc/gantry/gantry.policy.yaml"
if [ "${NO_STORE:-}" = 1 ]; then
  policy=test/.no-store.policy.yaml
  grep -v '^store:' test/gantry.test.policy.yaml > "$policy"
  key_flags=""
fi
export GANTRY_POLICY="./$policy"
compose="docker compose -p gantry-test --profile test"

cleanup() {
  status=$?
  [ $status -ne 0 ] && $compose logs gantry || true
  $compose down -v >/dev/null 2>&1 || true
  rm -f test/.no-store.policy.yaml
  exit $status
}
trap cleanup EXIT

[ -n "${GANTRY_IMAGE:-}" ] || $compose build gantry cli
$compose up -d postgres mock
# Before Gantry starts: without a store, `serve` needs the keys file this creates.
# shellcheck disable=SC2086
key=$($compose run --rm -T cli key new ci.tester --team platform --keys /var/lib/gantry/gantry.keys.yaml $key_flags --quiet | tail -n 1)
case "$key" in gantry_*) ;; *) echo "key new printed no key: $key"; exit 1 ;; esac

$compose up -d gantry

url="http://127.0.0.1:$GANTRY_PORT"
i=0
until curl -fsS "$url/healthz" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 60 ] || { echo "gantry did not answer /healthz within 60 s"; exit 1; }
  sleep 1
done
echo "healthz: $(curl -fsS "$url/healthz")"

i=0
while :; do
  answer=$(curl -sS -w '\n%{http_code}' "$url/v1/chat/completions" \
    -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
    -d '{"model":"mock-model","messages":[{"role":"user","content":"ping"}]}')
  code=$(echo "$answer" | tail -n 1)
  [ "$code" = 200 ] && break
  i=$((i + 1)); [ $i -lt 10 ] || { echo "governed call failed: $answer"; exit 1; }
  sleep 1
done
echo "$answer" | head -n 1 | grep -q pong || { echo "unexpected answer: $answer"; exit 1; }
echo "governed call: 200, answer from the mock"

# Without a key the gateway refuses: the call above went through the policy, not around it.
code=$(curl -sS -o /dev/null -w '%{http_code}' "$url/v1/chat/completions" -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"ping"}]}')
[ "$code" = 401 ] || { echo "a call without a key got $code, not 401"; exit 1; }
echo "call without a key: 401"

$compose run --rm -T cli audit verify /var/lib/gantry/gantry-audit.jsonl
echo "compose test passed"
