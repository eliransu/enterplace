"""The release version: Cargo.toml, CHANGELOG.md and the tag must agree.

Usage:
  python3 scripts/version.py [--root DIR] [vX.Y.Z]        check (exit 1 with the fix when they disagree)
  python3 scripts/version.py [--root DIR] --notes         print the CHANGELOG section of the Cargo.toml version
  python3 scripts/version.py [--root DIR] --bump X.Y.Z    set Cargo.toml to X.Y.Z and date its CHANGELOG section today
  python3 scripts/version.py --selftest

DIR is a repository root (default: this one): gantry or gantry-enterprise, which share one version.
Without a tag, CHANGELOG.md needs a section for the Cargo.toml version, dated or "Unreleased". With a tag, the tag is
v<Cargo.toml version> and the section is dated (YYYY-MM-DD) and not empty.
"""
import datetime, pathlib, re, sys, tempfile

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
    return problems


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
    print("PASS  version selftest")


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
