# Releasing Gantry

Gantry ships under one semantic version, X.Y.Z, from this one repository: the open source crates and the enterprise
crate in `enterprise/` share the workspace version. A release is one `vX.Y.Z` tag. Nothing is published outside the
private repository and package: the release is a GitHub Release of eliransu/gantry, and the image goes to the private
package `ghcr.io/eliransu/gantry` (named `ghcr.io/eliransu/gantry-enterprise` before 0.1.0).

## Versions

- A patch (0.1.1) fixes without changing behavior anyone relies on. A minor (0.2.0) adds features, and before 1.0 may
  change behavior, said under `### Changed` in the CHANGELOG. Major versions start at 1.0.0.
- Every change a user or operator can see goes under `## [Unreleased]` in CHANGELOG.md, grouped by feature in plain
  language, in the same pull request. Enterprise features say so.
- `scripts/version.py` checks that Cargo.toml, CHANGELOG.md and the Helm chart name one version. CI runs it on every
  push (scripts/ci.sh, and the version job of image.yml) and strictly on every tag.

## Steps

Run these at the repository root, on `main`, with nothing uncommitted.

1. Bump. The script sets the version in Cargo.toml, Cargo.lock and the Helm chart, and turns
   `## [X.Y.Z] - Unreleased` (or else `## [Unreleased]`) into `## [X.Y.Z] - <today>`:

   ```bash
   scripts/release.sh bump X.Y.Z
   ```

2. Read the CHANGELOG section once more, then commit and push to main (or merge a pull request):

   ```bash
   git commit -am "Release X.Y.Z"
   git push origin main
   ```

   Wait for CI to pass on main.

3. Tag:

   ```bash
   git tag -a vX.Y.Z -m "Gantry X.Y.Z" && git push origin vX.Y.Z
   ```

4. Check the GitHub Release (below) and pull the image by its digest once.

## What the tag starts

| Workflow | Result |
|---|---|
| `.github/workflows/release.yml` | Checks the tag against Cargo.toml and the dated CHANGELOG section. Builds the linux amd64 and arm64 tarballs twice from scratch and fails unless both builds are the same bytes. Runs the rollback check (the previous tag's binary reads this one's data) and the mixed-version check (the previous tag and this one serve from one Postgres at once, `scripts/mixed_version_check.py`). Packages the Helm chart, pushes it to `oci://ghcr.io/eliransu/charts` and signs it with cosign, keyless. Writes `SHA256SUMS` and SLSA provenance and signs both with `RELEASE_SIGNING_KEY`'s SSH key, verified against `release/allowed_signers`. Adds the tarballs, checksums, provenance and signatures to the private GitHub Release `vX.Y.Z`, creating it with the CHANGELOG section as its notes if image.yml has not yet. |
| `.github/workflows/image.yml` | Checks the version against the tag. Builds the image for amd64 and arm64, pushes it to `ghcr.io/eliransu/gantry` tagged `X.Y.Z` and the commit SHA, scans it (`scripts/scan_image.sh`, fails on high or critical), signs it with cosign keyless and attaches its CycloneDX SBOM and SLSA provenance as signed attestations. Then puts the image and its digest at the top of the GitHub Release `vX.Y.Z` (creating it if release.yml has not yet), with `sbom.cdx.json`. |
| `.github/workflows/codeql.yml` | Not started by the tag: CodeQL on the Rust code and the workflows on every pull request, push to main and weekly. |

Pushes to main keep publishing `latest` and the commit SHA. Production pins `X.Y.Z` or, better, the digest from the
release notes.

To check a user's download: `scripts/release.sh verify`, with the release files in `dist/`. To check the image, its
SBOM and provenance, and the chart: `scripts/verify_release.sh X.Y.Z` (docs: Operations, Verify a release).

Keyless signing needs nothing set up: the workflows' `id-token: write` permission is the identity. The signatures and
their certificates (which name this repository, the workflow and the tag) are recorded in Sigstore's public
transparency log. Code scanning results from CodeQL need GitHub code security enabled on this private repository.

## Dry run

Both workflows run without a tag, publishing nothing:

```bash
gh workflow run release.yml --repo eliransu/gantry --ref <branch>
gh workflow run image.yml --repo eliransu/gantry --ref <branch>
```

release.yml dates the CHANGELOG in its runner only, checks it as a tag would be checked, builds, compares, signs and
verifies, and its publish job prints the release it would create instead of creating it. image.yml checks the
version, builds both architectures and pushes nothing.

## Rolling upgrades and migrations

Two versions one minor version apart share one database, so replicas are replaced one at a time. That holds only if
every store migration is expand-only:

- A migration (an entry in `MIGRATIONS` in crates/gantry-server/src/store.rs, or a namespace's list) only adds:
  tables, nullable columns or columns with defaults, indexes. Code of version N must keep working when N+1's
  migrations have run.
- Removing or renaming anything version N reads waits until N+2: that version and N can never share the database,
  because N refuses a database whose recorded newest version (`gantry_writer`) is two minor versions ahead.
- Every start records its version in `gantry_writer` when it is newer than the one there. A binary facing a schema
  ahead of its own accepts it only when that version is strictly newer and at most one minor version ahead (a major
  version counts as one step from its last minor), and otherwise refuses with both versions named.
- A release that adds a migration is a minor release. `scripts/version.py` refuses a version that is not a minor
  version above the previous tag when any migration list changed since that tag, in any namespace, open source or
  enterprise, and names the namespace. It reads the fingerprints in `release/migrations.txt` and
  `enterprise/migrations.txt`; the test `the_migration_fingerprints_file_matches_the_code` of gantry-server and of
  gantry-enterprise fails when a file is behind the code and says how to write it again
  (`GANTRY_WRITE_MIGRATIONS=1 cargo test -p gantry-server the_migration_fingerprints_file_matches_the_code`, and
  the same with `-p gantry-enterprise`). The check needs the tags: clone with history.
- `scripts/mixed_version_check.py` runs in release.yml against the previous tag. The store test
  `serve_refuses_to_start_without_its_store_or_on_a_newer_schema` covers the one-minor and two-minor cases.

## Rolling back

A release is never moved or deleted: a tag and an image tag, once pulled, may be pinned somewhere.

1. Deployments go back to the previous version: `image.tag: X.Y.(Z-1)` in the Helm values, the previous tag or digest in
   the Compose file or Terraform `image` variable, or the previous release's tarball. `scripts/rollback_check.py` runs
   on every release, so the previous binary reads the data of the new one: the audit log stays one verified chain.
2. A release that applied a store migration (its CHANGELOG says so) cannot be rolled back onto that database: an
   older Gantry refuses a newer schema. Restore the backup taken before the upgrade, or stay and fix forward.
3. Mark the bad GitHub Release: edit the title to start with `Withdrawn:` and say why at the top of the notes.
4. Fix on main and ship X.Y.(Z+1) with the steps above, saying under `### Fixed` what went wrong.

A tag pushed by mistake, before anyone pulled it: delete the GitHub Release, then the tag (`git push origin
:refs/tags/vX.Y.Z`), and delete the image version from the package page on GitHub.
