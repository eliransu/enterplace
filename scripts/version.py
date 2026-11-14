"""The release version: Cargo.toml, CHANGELOG.md and the tag must agree.

Usage:
  python3 scripts/version.py [--root DIR] [vX.Y.Z]        check (exit 1 with the fix when they disagree)
  python3 scripts/version.py [--root DIR] --notes         print the CHANGELOG section of the Cargo.toml version
  python3 scripts/version.py [--root DIR] --bump X.Y.Z    set Cargo.toml to X.Y.Z and date its CHANGELOG section today
  python3 scripts/version.py --selftest

DIR is a repository root (default: this one). The open source crates and enterprise/ share the workspace version.
Without a tag, CHANGELOG.md needs a section for the Cargo.toml version, dated or "Unreleased". With a tag, the tag is
v<Cargo.toml version> and the section is dated (YYYY-MM-DD) and not empty.

Once a release tag exists, a store migration list that changed since the previous tag (any namespace, open source or
enterprise) needs a minor version above that tag's: two versions share one database only one minor version apart
(RELEASING.md, "Rolling upgrades and migrations"). The lists are compared by the fingerprint files a test of each
crate keeps (MANIFESTS). The previous tag is the newest vX.Y.Z tag reachable from HEAD that is not on HEAD itself, so
the clone needs its tags and history (actions/checkout: fetch-depth: 0); with none in reach the check is skipped.
"""
import datetime, pathlib, re, subprocess, sys, tempfile

SEMVER = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?"


def cargo_version(root):
    match = re.search(r'^version = "(.+)"', (root / "Cargo.toml").read_text(), re.M)
    if not match:
        raise SystemExit(f"{root / 'Cargo.toml'} has no version line.")
    return match.group(1)


def section(root, version):
    """The CHANGELOG heading's date (or "Unreleased") and the text under it, or None when there is no heading."""
    text = (root / "CHANGELOG.md").read_text() if (root / "CHANGELOG.md").exists() else ""
    match = re.search(rf"^## \[{re.escape(version)}\] - (\S+)\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return (match.group(1), match.group(2).strip()) if match else None


# The fingerprint files: release/migrations.txt (gantry-server) and enterprise/migrations.txt (gantry-enterprise).
MANIFESTS = ("release/migrations.txt", "enterprise/migrations.txt")


def fingerprints(text):
    """A fingerprint file as {namespace: "entries hash"}."""
    lines = (line.split(None, 1) for line in text.splitlines() if line.strip() and not line.startswith("#"))
    return {parts[0]: parts[-1].strip() for parts in lines}


def changed_namespaces(old, new):
    """The namespaces whose migration list differs between two fingerprint files: added to, edited, new or gone."""
    old, new = fingerprints(old), fingerprints(new)
    return sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))


def git(root, *args):
    """A git command's output in `root`, or None when it fails (no repository, no such tag or file)."""
    try:
        done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    except OSError:
        return None
    return done.stdout if done.returncode == 0 else None


def previous_tag(root):
    """The newest release tag before HEAD's own, or None: not a repository, no tag yet, or a clone without tags."""
    here = [f"--exclude={tag}" for tag in (git(root, "tag", "--points-at", "HEAD") or "").split()]
    found = git(root, "describe", "--tags", "--abbrev=0", "--match=v[0-9]*", *here, "HEAD")
    return found.strip() if found else None


def migration_problems(root, version):
    """A problem for each namespace whose migrations changed since the previous tag without a minor version bump."""
    tag = previous_tag(root)
    before = re.fullmatch(r"v(\d+)\.(\d+)\.\d+.*", tag or "")
    if not before:
        return []
    before = (int(before.group(1)), int(before.group(2)))
    if tuple(int(part) for part in version.split(".")[:2]) > before:
        return []
    problems = []
    for path in MANIFESTS:
        old = git(root, "show", f"{tag}:{path}")
        if old is None:  # The tag is from before the fingerprint file: nothing to compare with.
            continue
        new = (root / path).read_text() if (root / path).exists() else ""
        for namespace in changed_namespaces(old, new):
            problems.append(
                f"{root / path}: the store migrations of namespace {namespace} changed since {tag}, and version {version} is not a minor version above it. "
                f"A gateway of {tag} could not share the database with this one during a rolling upgrade. "
                f"Bump the minor version: scripts/release.sh bump {before[0]}.{before[1] + 1}.0. "
                f"If a migration that shipped in {tag} was edited, undo that and add a new entry instead.")
    return problems


def check(root, tag=None):
    """The problems, each with its fix. Empty when the version is ready."""
    version = cargo_version(root)
    if not re.fullmatch(SEMVER, version):
        return [f"{root / 'Cargo.toml'}: version {version} is not a semantic version (X.Y.Z)."]
    problems = []
    if tag is not None and tag != f"v{version}":
        problems.append(f"tag {tag} does not match version {version} in {root / 'Cargo.toml'}. Bump with scripts/release.sh bump {tag.lstrip('v')}, or tag v{version}.")
    chart = root / "deploy/helm/gantry/Chart.yaml"
    if chart.exists() and f'appVersion: "{version}"' not in chart.read_text():
        problems.append(f"{chart}: appVersion is not \"{version}\". Run scripts/release.sh bump {version}.")
    found = section(root, version)
    if found is None:
        problems.append(f"{root / 'CHANGELOG.md'} has no section \"## [{version}] - YYYY-MM-DD\". Write the changes under ## [Unreleased], then run scripts/release.sh bump {version}.")
    elif tag is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", found[0]):
        problems.append(f"{root / 'CHANGELOG.md'}: section {version} is dated \"{found[0]}\", not a release date. Run scripts/release.sh bump {version}.")
    elif tag is not None and not found[1]:
        problems.append(f"{root / 'CHANGELOG.md'}: section {version} is empty. Say what changed before tagging.")
    return problems + migration_problems(root, version)


def bump(root, version, today=None):
    """Sets the version and turns "## [X.Y.Z] - Unreleased", or else "## [Unreleased]", into today's section."""
    if not re.fullmatch(SEMVER, version):
        raise SystemExit(f"{version} is not a semantic version (X.Y.Z).")
    today = today or datetime.date.today().isoformat()
    log = root / "CHANGELOG.md"
    text = log.read_text() if log.exists() else ""
    if f"## [{version}] - Unreleased" in text:
        text = text.replace(f"## [{version}] - Unreleased", f"## [{version}] - {today}", 1)
    elif section(root, version) is None and "## [Unreleased]\n" in text:
        text = text.replace("## [Unreleased]\n", f"## [Unreleased]\n\n## [{version}] - {today}\n", 1)
    elif section(root, version) is None:
        raise SystemExit(f"{log} has neither \"## [{version}] - Unreleased\" nor \"## [Unreleased]\". Write the changes there first.")
    # The CHANGELOG is settled first, so a refusal leaves Cargo.toml as it was.
    cargo = root / "Cargo.toml"
    # Every `version = "<old>"`: the package's own and the workspace's path dependencies on its crates.
    old = cargo_version(root)
    cargo.write_text(cargo.read_text().replace(f'version = "{old}"', f'version = "{version}"'))
    log.write_text(text)
    chart = root / "deploy/helm/gantry/Chart.yaml"
    if chart.exists():
        chart.write_text(re.sub(r'^version: .+$', f"version: {version}", re.sub(r'^appVersion: .+$', f'appVersion: "{version}"', chart.read_text(), flags=re.M), flags=re.M))


def selftest():
    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n[workspace.dependencies]\na = { path = "a", version = "0.1.0" }\n')
        (root / "CHANGELOG.md").write_text("# Changelog\n\n## [0.1.0] - Unreleased\n\n### Added\n\n- A thing.\n")
        assert check(root) == [], check(root)
        assert any("not a release date" in p for p in check(root, "v0.1.0"))
        (root / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-20\n\n- A thing.\n\n## [0.0.9] - 2026-11-01\n\n- Old.\n")
        assert check(root, "v0.1.0") == [], check(root, "v0.1.0")
        assert section(root, "0.1.0") == ("2026-11-20", "- A thing.")
        assert any("does not match" in p for p in check(root, "v0.1.1"))
        (root / "CHANGELOG.md").write_text("# Changelog\n\n## [0.1.0] - 2026-11-20\n\n## [0.0.9] - 2026-11-01\n\n- Old.\n")
        assert any("is empty" in p for p in check(root, "v0.1.0"))
        (root / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n\n- New.\n\n## [0.1.0] - 2026-11-20\n\n- A thing.\n")
        bump(root, "0.1.1", "2026-12-01")
        assert '"a", version = "0.1.1"' in (root / "Cargo.toml").read_text()
        assert cargo_version(root) == "0.1.1" and check(root, "v0.1.1") == [], check(root, "v0.1.1")
        assert section(root, "0.1.1") == ("2026-12-01", "- New.") and section(root, "0.1.0") == ("2026-11-20", "- A thing.")
        (root / "deploy/helm/gantry").mkdir(parents=True)
        (root / "deploy/helm/gantry/Chart.yaml").write_text('name: gantry\nversion: 0.0.1\nappVersion: "0.0.1"\n')
        assert any("appVersion" in p for p in check(root))
        bump(root, "0.1.1")
        assert (root / "deploy/helm/gantry/Chart.yaml").read_text() == 'name: gantry\nversion: 0.1.1\nappVersion: "0.1.1"\n'
        (root / "Cargo.toml").write_text('version = "0.2.0"\n')
        assert any("no section" in p for p in check(root))
    migrations_selftest()
    print("PASS  version selftest")


def migrations_selftest():
    old = "# note\ncore 2 aaa\nenterprise.watch 1 bbb\nmcp 1 ccc\n"
    assert changed_namespaces(old, old) == []
    assert changed_namespaces(old, "core 3 ddd\nenterprise.watch 1 bbb\nmcp 1 ccc\n") == ["core"]
    assert changed_namespaces(old, "core 2 aaa\nenterprise.watch 1 eee\nmcp 1 ccc\n") == ["enterprise.watch"]
    assert changed_namespaces(old, "core 2 aaa\nmcp 1 ccc\nbatches 1 fff\n") == ["batches", "enterprise.watch"]
    # A repository as a release leaves it: tagged, then a migration added in each fingerprint file.
    with tempfile.TemporaryDirectory() as folder:
        root = pathlib.Path(folder)
        run = lambda *args: subprocess.run(["git", "-C", folder, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args], check=True, capture_output=True)
        commit = lambda note: (run("add", "-A"), run("commit", "-q", "-m", note))
        cargo = lambda version: (root / "Cargo.toml").write_text(f'version = "{version}"\n')
        log = lambda text: (root / "CHANGELOG.md").write_text("# Changelog\n\n" + text)
        (root / "release").mkdir()
        (root / "enterprise").mkdir()
        run("init", "-q")
        cargo("0.1.0")
        log("## [0.1.0] - 2026-11-20\n\n- First.\n")
        (root / "release/migrations.txt").write_text("core 2 aaa\nmcp 1 ccc\n")
        (root / "enterprise/migrations.txt").write_text("enterprise.watch 1 bbb\n")
        # Before the first tag nothing is compared.
        commit("first")
        assert check(root) == [], check(root)
        run("tag", "v0.1.0")
        assert check(root, "v0.1.0") == [], check(root, "v0.1.0")
        # A patch release that touches no migration passes.
        cargo("0.1.1")
        log("## [0.1.1] - 2026-11-21\n\n- Fix.\n\n## [0.1.0] - 2026-11-20\n\n- First.\n")
        commit("fix")
        assert check(root) == [], check(root)
        # A migration added without a bump at all, then with a patch bump only: refused, naming the namespace and the fix.
        (root / "release/migrations.txt").write_text("core 3 ddd\nmcp 1 ccc\n")
        (root / "enterprise/migrations.txt").write_text("enterprise.watch 2 eee\n")
        for version in ("0.1.0", "0.1.1"):
            cargo(version)
            problems = check(root)
            assert len(problems) == 2 and "namespace core changed since v0.1.0" in problems[0], problems
            assert "namespace enterprise.watch changed" in problems[1] and "release.sh bump 0.2.0" in problems[1], problems
        commit("migrations")
        run("tag", "v0.1.1")
        # On the tag itself the comparison is still with the tag before it.
        assert len(check(root, "v0.1.1")) == 2, check(root, "v0.1.1")
        run("tag", "-d", "v0.1.1")
        # The minor bump passes, on the commit and on its tag.
        cargo("0.2.0")
        log("## [0.2.0] - 2026-12-01\n\n- Tables.\n")
        commit("minor")
        assert check(root) == [], check(root)
        run("tag", "v0.2.0")
        assert check(root, "v0.2.0") == [], check(root, "v0.2.0")


def main():
    args = sys.argv[1:]
    if args == ["--selftest"]:
        return selftest()
    root = pathlib.Path(__file__).resolve().parent.parent
    if args[:1] == ["--root"]:
        root, args = pathlib.Path(args[1]).resolve(), args[2:]
    if args[:1] == ["--bump"] and len(args) == 2:
        return bump(root, args[1])
    if args == ["--notes"]:
        found = section(root, cargo_version(root))
        if not found:
            raise SystemExit(f"{root / 'CHANGELOG.md'} has no section for {cargo_version(root)}.")
        return print(found[1])
    problems = check(root, args[0] if args else None)
    if problems:
        raise SystemExit("\n".join(problems))
    print(f"{root.name}: version {cargo_version(root)} {'matches ' + args[0] + ' and ' if args else 'has '}a CHANGELOG section")


if __name__ == "__main__":
    main()
