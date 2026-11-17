#!/usr/bin/env bash
# The checks CI runs (.github/workflows/ci.yml), in the same order, on this machine. Stops at the first that fails.
#
#   scripts/ci.sh            everything
#   scripts/ci.sh --no-bench everything but the bench gate, for a machine too busy to time anything
set -euo pipefail
cd "$(dirname "$0")/.."
bench=1
[ "${1:-}" = "--no-bench" ] && bench=0

step() { printf '\n== %s\n' "$*"; }

step "format"
cargo fmt --all --check
step "lint"
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
step "the open source crates do not depend on enterprise/"
# License code lives only in enterprise/ (AGENTS.md rule 6): no open crate may pull it in, in any dependency kind.
for crate in enterplace-core enterplace-server enterplace-console enterplace-cli enterplace-bench; do
  if cargo tree --locked -q -p "$crate" -e normal,build,dev --prefix none | grep -q '^enterplace-enterprise '; then
    echo "$crate depends on enterplace-enterprise"; exit 1
  fi
done
echo "none does"
step "tests"
# The store tests (crates/enterplace-server/tests/store.rs, crates/enterplace-cli/tests/store.rs) run against the Postgres
# that ENTERPLACE_TEST_DATABASE_URL names, and say they were skipped without it. CI must run them.
if [ -n "${ENTERPLACE_TEST_DATABASE_URL:-}" ]; then
  echo "store tests run against Postgres (ENTERPLACE_TEST_DATABASE_URL is set)"
elif [ -n "${CI:-}" ]; then
  echo "ENTERPLACE_TEST_DATABASE_URL is not set: CI must run the store tests against Postgres. See .github/workflows/ci.yml."
  exit 1
else
  echo "store tests skipped: set ENTERPLACE_TEST_DATABASE_URL, for example after"
  # Each test drops its database when it ends, so the container stays the size it started.
  echo "  docker run -d --name enterplace-pg -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16"
  echo "  export ENTERPLACE_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres"
fi
cargo test --workspace --locked
# The enterprise crate once more with every feature (`issuer`, the license signing commands of staff builds).
cargo test -p enterplace-enterprise --all-features --locked
step "release build"
cargo build --release --locked
./target/release/enterplace version
step "the enterprise binary without a license key is the open source edition"
./target/release/enterplace-enterprise version
env -u ENTERPLACE_LICENSE -u ENTERPLACE_LICENSE_FILE ./target/release/enterplace-enterprise license show | tee /dev/stderr | grep -qi "no license"
step "the binary refuses to forward unchecked unless asked by name"
if ./target/release/enterplace serve 2>/dev/null; then echo "serve started without --unchecked"; exit 1; fi
step "first run: init, serve, the setup link and a governed call, in under 60 seconds"
python3 scripts/first_run_check.py target/release/enterplace
step "the new user's path: install, enterplace start, the dashboard link in Chrome, a first request (scripts/ftue_check.py)"
ftue_chrome=""
for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium; do
  if command -v "$c" >/dev/null 2>&1; then ftue_chrome="$c"; break; fi
done
if [ -n "$ftue_chrome" ]; then
  python3 scripts/ftue_check.py --enterplace target/release/enterplace --chrome "$ftue_chrome"
else
  echo "skipped: Chrome is not installed (google-chrome, chromium, or Google Chrome.app). Install it to run this check."
fi
step "the live provider matrix passes every cell against mocks and skips every cell without keys"
python3 scripts/live_matrix.py --selftest --enterplace target/release/enterplace > /dev/null
step "Cargo.toml, CHANGELOG.md and the Helm chart name one version"
python3 scripts/version.py --selftest
python3 scripts/version.py
step "the Helm chart: lint, render, security settings, its policy passes enterplace check"
python3 scripts/check_deploy.py target/release/enterplace
step "every policy example in README and the docs passes enterplace check"
python3 scripts/check_examples.py target/release/enterplace
step "the website serves the same install.sh as the repository root"
# enterplace.dev/install.sh is site/src/static/install.sh, copied into site/public by site/build.py.
cmp install.sh site/src/static/install.sh
cmp install.sh site/public/install.sh
if [ "$bench" = 1 ]; then
  step "bench gate (chat, 1,000 requests a second for 5 seconds, p99 overhead under 1,000 us, best of 3)"
  # One 5 s sample at p99 is at the mercy of whatever else the machine runs. A warm-up fills caches and wakes the
  # CPU, then up to three attempts run, each printed with the load it ran under. One pass is a pass: the gate is
  # unchanged, a regression fails all three. (docs/operations.md, "Bench")
  bench() { ./target/release/enterplace-bench --rps 1000 --secs "$@"; }
  cargo build --release --locked -q -p enterplace-bench
  echo "warm-up: $(uptime)"
  bench 2 > /dev/null || true
  passed=0
  for attempt in 1 2 3; do
    echo "attempt $attempt: $(uptime)"
    if bench 5 --max-p99-overhead-us 1000; then passed=1; break; fi
  done
  [ "$passed" = 1 ] || { echo "the bench gate failed in all 3 attempts"; exit 1; }
fi
step "the console's editing pages in a real Chrome against Postgres"
# Opt in by having all three: ENTERPLACE_TEST_DATABASE_URL, Chrome and psql (to make the check's own database). CI runs
# it as its own job (console-edit in .github/workflows/ci.yml), so it is not run twice there.
chrome=""
for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium; do
  if command -v "$c" >/dev/null 2>&1; then chrome="$c"; break; fi
done
if [ -n "${CI:-}" ]; then
  echo "skipped here: the console-edit job runs it."
elif [ -n "${ENTERPLACE_TEST_DATABASE_URL:-}" ] && [ -n "$chrome" ] && command -v psql >/dev/null; then
  cargo build --locked -q -p enterplace-cli
  url="$ENTERPLACE_TEST_DATABASE_URL"
  # A local test database, as the store tests use it: no TLS unless the URL asks for it.
  case "$url" in *sslmode=*) ;; *\?*) url="$url&sslmode=disable" ;; *) url="$url?sslmode=disable" ;; esac
  python3 scripts/console_edit_check.py --fresh --chrome "$chrome" --database "$url" --port 20760
else
  echo "skipped: needs ENTERPLACE_TEST_DATABASE_URL, Chrome and psql."
fi
step "console app build matches the committed one"
# The binary embeds crates/enterplace-console/app, built from console-ui. A source change without a rebuild fails here.
if command -v npm >/dev/null; then
  (cd console-ui && npm ci --no-audit --no-fund && npm run build)
  git diff --exit-code -- crates/enterplace-console/app
else
  echo "skipped: npm is not installed."
fi
step "docs build"
# The docs site needs Node. Without it this step says so instead of failing a Rust-only machine.
if command -v npm >/dev/null; then
  (cd docs && npm ci --no-audit --no-fund && npm run build)
else
  echo "skipped: npm is not installed."
fi
step "all checks passed"
