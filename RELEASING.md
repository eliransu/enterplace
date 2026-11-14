# Releasing Gantry

Gantry ships under one semantic version, X.Y.Z, from this one repository: the open source crates and the enterprise
crate in `enterprise/` share the workspace version. A release is one `vX.Y.Z` tag. Nothing is published outside the
private repository and package: the release is a GitHub Release of ggantry/gantry, and the image goes to the private
package `ghcr.io/ggantry/gantry` (named `ghcr.io/ggantry/gantry-enterprise` before 0.1.0).

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
| `.github/workflows/release.yml` | Checks the tag against Cargo.toml and the dated CHANGELOG section. Builds the linux amd64 and arm64 tarballs twice from scratch and fails unless both builds are the same bytes. Runs the rollback check (the previous tag's binary reads this one's data). Writes `SHA256SUMS` and SLSA provenance and signs both with `RELEASE_SIGNING_KEY`'s SSH key, verified against `release/allowed_signers`. Adds the tarballs, checksums, provenance and signatures to the private GitHub Release `vX.Y.Z`, creating it with the CHANGELOG section as its notes if image.yml has not yet. |
| `.github/workflows/image.yml` | Checks the version against the tag. Builds the image for amd64 and arm64, pushes it to `ghcr.io/ggantry/gantry` tagged `X.Y.Z` and the commit SHA, then puts the image and its digest at the top of the GitHub Release `vX.Y.Z` (creating it if release.yml has not yet). |

Pushes to main keep publishing `latest` and the commit SHA. Production pins `X.Y.Z` or, better, the digest from the
release notes.

To check a user's download: `scripts/release.sh verify`, with the release files in `dist/`.

## Dry run

Both workflows run without a tag, publishing nothing:

```bash
gh workflow run release.yml --repo ggantry/gantry --ref <branch>
gh workflow run image.yml --repo ggantry/gantry --ref <branch>
```

release.yml dates the CHANGELOG in its runner only, checks it as a tag would be checked, builds, compares, signs and
verifies, and its publish job prints the release it would create instead of creating it. image.yml checks the
version, builds both architectures and pushes nothing.

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
