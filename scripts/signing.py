"""Signs a release folder and checks a signed one.

  python3 scripts/signing.py sign <dist folder>     writes SHA256SUMS and provenance.json, and a .sig for each
  python3 scripts/signing.py verify <dist folder>   checks both signatures and every file's hash
  python3 scripts/signing.py predicate              prints the SLSA v1 predicate alone, for cosign attest

Signing uses an SSH key (`ssh-keygen -Y sign`, namespace gantry-release): the private key comes from
RELEASE_SIGNING_KEY (its text, as CI passes a secret) or GANTRY_SIGNING_KEY_FILE (a path). Verifying needs only
ssh-keygen and release/allowed_signers, the public key kept in this repository. provenance.json is an in-toto
statement with a SLSA v1 predicate: the commit, the build's inputs (Cargo.lock, Dockerfile, rust toolchain),
SOURCE_DATE_EPOCH, and the CI run that built it. Standard library only.
"""
import hashlib, json, os, pathlib, platform, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIGNERS = pathlib.Path(os.environ.get("GANTRY_ALLOWED_SIGNERS", ROOT / "release" / "allowed_signers"))  # the override is for tests
NAMESPACE = "gantry-release"
IDENTITY = "release@gantry"
SIGNED = ["SHA256SUMS", "provenance.json"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def artifacts(dist):
    return sorted(p for p in dist.iterdir() if p.is_file() and p.name not in SIGNED and not p.name.endswith(".sig"))


def provenance(files):
    env = os.environ
    run = f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}" if env.get("GITHUB_RUN_ID") else ""
    commit = git("rev-parse", "HEAD")
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": p.name, "digest": {"sha256": sha256(p)}} for p in files],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://gantry.dev/release/v1",
                "externalParameters": {"commit": commit, "ref": env.get("GITHUB_REF", git("rev-parse", "--abbrev-ref", "HEAD"))},
                "internalParameters": {
                    "SOURCE_DATE_EPOCH": env.get("SOURCE_DATE_EPOCH"),
                    "dockerfile_from": [l.split()[1] for l in (ROOT / "Dockerfile").read_text().splitlines() if l.startswith("FROM ")],
                },
                "resolvedDependencies": [
                    {"uri": "git+source", "digest": {"gitCommit": commit}},
                    {"name": "Cargo.lock", "digest": {"sha256": sha256(ROOT / "Cargo.lock")}},
                    {"name": "Dockerfile", "digest": {"sha256": sha256(ROOT / "Dockerfile")}},
                ],
            },
            "runDetails": {
                "builder": {"id": run or f"local:{platform.system().lower()}"},
                "metadata": {"invocationId": run or None},
            },
        },
    }


def key_file():
    text = os.environ.get("RELEASE_SIGNING_KEY", "")
    if text.strip():
        f = tempfile.NamedTemporaryFile("w", delete=False, prefix="gantry-signing-")
        os.chmod(f.name, 0o600)
        f.write(text if text.endswith("\n") else text + "\n")
        f.close()
        return f.name, True
    path = os.environ.get("GANTRY_SIGNING_KEY_FILE", "")
    if path and os.path.exists(path):
        return path, False
    sys.exit("error: no signing key. Set RELEASE_SIGNING_KEY to the private key's text (the CI secret), or GANTRY_SIGNING_KEY_FILE to its path.")


def sign(dist):
    files = artifacts(dist)
    if not files:
        sys.exit(f"error: nothing to sign in {dist}. Build the release first: scripts/release.sh linux")
    (dist / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    (dist / "provenance.json").write_text(json.dumps(provenance(files), indent=2) + "\n")
    key, temporary = key_file()
    try:
        for name in SIGNED:
            sig = dist / f"{name}.sig"
            sig.unlink(missing_ok=True)
            subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", NAMESPACE, str(dist / name)], check=True, capture_output=True)
    finally:
        if temporary:
            os.unlink(key)
    print(f"signed {len(files)} files in {dist}: SHA256SUMS, provenance.json and their .sig")


def verify(dist):
    if not SIGNERS.exists():
        sys.exit(f"error: {SIGNERS} is missing: it holds the release public key.")
    problems = []
    for name in SIGNED:
        path, sig = dist / name, dist / f"{name}.sig"
        if not path.exists() or not sig.exists():
            problems.append(f"{name} or its .sig is missing")
            continue
        with open(path, "rb") as data:
            ok = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(SIGNERS), "-I", IDENTITY, "-n", NAMESPACE, "-s", str(sig)],
                                stdin=data, capture_output=True, text=True)
        if ok.returncode != 0:
            problems.append(f"{name}: the signature does not verify against {SIGNERS.name} ({ok.stderr.strip() or ok.stdout.strip()})")
    sums = {}
    if (dist / "SHA256SUMS").exists():
        for line in (dist / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ", 1)
            sums[name] = digest
            if not (dist / name).exists():
                problems.append(f"{name} is listed in SHA256SUMS and missing")
            elif sha256(dist / name) != digest:
                problems.append(f"{name} does not match its hash in SHA256SUMS: it changed after signing")
        for p in artifacts(dist):
            if p.name not in sums:
                problems.append(f"{p.name} is not in SHA256SUMS: it was not signed")
    if (dist / "provenance.json").exists():
        subjects = {s["name"]: s["digest"]["sha256"] for s in json.loads((dist / "provenance.json").read_text())["subject"]}
        if subjects != sums:
            problems.append("provenance.json names other files or hashes than SHA256SUMS")
    if problems:
        print("NOT VERIFIED\n  " + "\n  ".join(problems))
        sys.exit(1)
    print(f"verified: {len(sums)} files, signed by {IDENTITY}")


if __name__ == "__main__":
    # The SLSA predicate alone, for `cosign attest --type slsaprovenance1`: cosign makes the statement around it, with
    # the image digest as its subject.
    if sys.argv[1:] == ["predicate"]:
        print(json.dumps(provenance([])["predicate"], indent=2))
        sys.exit(0)
    if len(sys.argv) != 3 or sys.argv[1] not in ("sign", "verify"):
        sys.exit(__doc__)
    {"sign": sign, "verify": verify}[sys.argv[1]](pathlib.Path(sys.argv[2]))
