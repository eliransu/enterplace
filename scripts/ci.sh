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
step "tests"
# The store tests (crates/gantry-server/tests/store.rs, crates/gantry-cli/tests/store.rs) run against the Postgres
# that GANTRY_TEST_DATABASE_URL names, and say they were skipped without it. CI must run them.
if [ -n "${GANTRY_TEST_DATABASE_URL:-}" ]; then
  echo "store tests run against Postgres (GANTRY_TEST_DATABASE_URL is set)"
elif [ -n "${CI:-}" ]; then
  echo "GANTRY_TEST_DATABASE_URL is not set: CI must run the store tests against Postgres. See .github/workflows/ci.yml."
  exit 1
else
  echo "store tests skipped: set GANTRY_TEST_DATABASE_URL, for example after"
  echo "  docker run -d --name gantry-pg -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16"
  echo "  export GANTRY_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres"
fi
cargo test --workspace --locked
step "release build"
cargo build --release --locked
./target/release/gantry version
step "the binary refuses to forward unchecked unless asked by name"
if ./target/release/gantry serve 2>/dev/null; then echo "serve started without --unchecked"; exit 1; fi
step "first run: init, serve, the setup link and a governed call, in under 60 seconds"
python3 scripts/first_run_check.py target/release/gantry
step "the live provider matrix passes every cell against mocks and skips every cell without keys"
python3 scripts/live_matrix.py --selftest --gantry target/release/gantry > /dev/null
step "Cargo.toml, CHANGELOG.md and the Helm chart name one version"
python3 scripts/version.py --selftest
python3 scripts/version.py
step "every policy example in README and the docs passes gantry check"
python3 scripts/check_examples.py target/release/gantry
if [ "$bench" = 1 ]; then
  step "bench gate (chat, 1,000 requests a second for 5 seconds, p99 overhead under 1,000 us, best of 3)"
  # One 5 s sample at p99 is at the mercy of whatever else the machine runs. A warm-up fills caches and wakes the
  # CPU, then up to three attempts run, each printed with the load it ran under. One pass is a pass: the gate is
  # unchanged, a regression fails all three. (docs/operations.md, "Bench")
  bench() { ./target/release/gantry-bench --rps 1000 --secs "$@"; }
  cargo build --release --locked -q -p gantry-bench
  echo "warm-up: $(uptime)"
  bench 2 > /dev/null || true
  passed=0
  for attempt in 1 2 3; do
    echo "attempt $attempt: $(uptime)"
    if bench 5 --max-p99-overhead-us 1000; then passed=1; break; fi
  done
  [ "$passed" = 1 ] || { echo "the bench gate failed in all 3 attempts"; exit 1; }
fi
step "docs build"
# The docs site needs Node. Without it this step says so instead of failing a Rust-only machine.
if command -v npm >/dev/null; then
  (cd docs && npm ci --no-audit --no-fund && npm run build)
else
  echo "skipped: npm is not installed."
fi
step "all checks passed"
