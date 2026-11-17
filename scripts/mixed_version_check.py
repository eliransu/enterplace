"""Two versions on one Postgres at the same time, as during a rolling upgrade.

Usage: DATABASE_URL=postgres://... python3 scripts/mixed_version_check.py <old enterplace binary> <new enterplace binary>
DATABASE_URL names an empty database (or one only these versions have used); the check makes its tables there.

The old version starts first and creates the store's tables. Traffic runs against it without a break while the new
version starts on the same database and applies its migrations. Then both serve at once: a key issued by either
version is accepted by both, and the old version, restarted on the schema the new one moved ahead (a pod of the old
version restarting mid-rollout), still starts. Both verify their own audit chains at the end.

The guarantee is one minor version apart (RELEASING.md, "Rolling upgrades"). An old binary that predates the rule
refuses any newer schema at restart; then that step says SKIP, naming why, instead of failing.
Standard library only, plus psql when it is on PATH to print the schema versions.
"""
import atexit, os, pathlib, shutil, subprocess, sys, tempfile, threading, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from rollback_check import FAILED, Provider, Serving, check, run  # noqa: E402

import http.server  # noqa: E402


def schema(url):
    if not shutil.which("psql"):
        return "unknown (psql not on PATH)"
    out = subprocess.run(["psql", url, "-tAc", "SELECT max(version) FROM enterplace_schema"], capture_output=True, text=True)
    return out.stdout.strip() or out.stderr.strip()


def skip_or_fail(name, said):
    """An old binary from before the one-minor-version rule refuses any newer schema: that is a SKIP, not a FAIL."""
    if "newer Enterplace" in said and "one minor version apart" not in said:
        print(f"SKIP  {name}: the old version predates the one-minor-version rule and refuses any newer schema")
    else:
        check(name, False, said)


def until(ok, seconds=5):
    end = time.time() + seconds
    while time.time() < end:
        if ok():
            return True
        time.sleep(0.2)
    return False


class Replica(Serving):
    """A gateway that is stopped when this script exits, however it exits."""

    def __init__(self, *args):
        super().__init__(*args)
        atexit.register(lambda: self.proc.poll() is None and self.proc.kill())


def main():
    url = os.environ.get("DATABASE_URL", "")
    if len(sys.argv) != 3 or not url:
        sys.exit(__doc__)
    old, new = (str(pathlib.Path(p).resolve()) for p in sys.argv[1:])
    print(f"old: {run(old, 'version').stdout.strip()}\nnew: {run(new, 'version').stdout.strip()}")
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()

    # One folder per replica, as each pod has its own volume: its own audit chain, the same policy and database.
    def replica(name):
        folder = pathlib.Path(tempfile.mkdtemp(prefix=f"enterplace-mixed-{name}-"))
        (folder / "enterplace.policy.yaml").write_text(f"""version: 1
audit: {{ path: {folder / 'enterplace-audit.jsonl'} }}
store: {{ postgres_url_env: DATABASE_URL }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{provider.server_address[1]}
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [model-a]
""")
        return folder

    a, b = replica("old"), replica("new")

    def key(binary, folder, name):
        out = run(binary, "key", "new", name, "--team", "eng", "--keys", str(folder / "enterplace.keys.yaml"),
                  "--policy", str(folder / "enterplace.policy.yaml"), "--quiet", check=False)
        if out.returncode:
            raise SystemExit(f"{binary} key new failed:\n{out.stdout}{out.stderr}")
        return out.stdout.strip()

    first = key(old, a, "first@example.com")
    g_old = Replica(old, a)
    print(f"schema after the old version started: {schema(url)}")
    check("the old version serves", g_old.chat(first) == 200)

    # Traffic to the old version without a break while the new one starts and migrates.
    stop, statuses = threading.Event(), []

    def traffic():
        while not stop.is_set():
            statuses.append(g_old.chat(first))
            time.sleep(0.02)

    t = threading.Thread(target=traffic)
    t.start()
    g_new = Replica(new, b)
    time.sleep(1)
    stop.set()
    t.join()
    print(f"schema after the new version started: {schema(url)}")
    check(f"the old version answered all {len(statuses)} requests while the new one started and migrated",
          statuses and all(s == 200 for s in statuses), f"statuses seen: {sorted(set(statuses))}")

    check("the new version serves a key the old one issued", g_new.chat(first) == 200)
    second = key(new, b, "second@example.com")
    check("the new version serves, within 5 seconds, a key it issued", until(lambda: g_new.chat(second) == 200))
    check("the old version serves, within 5 seconds, a key the new one issued", until(lambda: g_old.chat(second) == 200))
    try:
        third = key(old, a, "third@example.com")
        check("the new version serves, within 5 seconds, a key the old one issued after the upgrade began",
              until(lambda: g_new.chat(third) == 200))
    except SystemExit as refused:
        skip_or_fail("the old version's key new on the newer schema", str(refused))

    # A pod of the old version restarting mid-rollout, on the schema the new version moved ahead.
    g_old.stop()
    try:
        g_old = Replica(old, a)
        check("the old version restarts on the newer schema and serves", g_old.chat(second) == 200)
        g_old.stop()
    except SystemExit as refused:
        skip_or_fail("the old version restarts on the newer schema", str(refused))
    g_new.stop()

    for name, binary, folder in (("old", old, a), ("new", new, b)):
        v = run(binary, "audit", "verify", str(folder / "enterplace-audit.jsonl"), check=False)
        check(f"the {name} version verifies its chain", v.returncode == 0, v.stdout + v.stderr)
    provider.shutdown()
    print("\nall passed" if not FAILED else f"\nFAILED: {', '.join(FAILED)}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
