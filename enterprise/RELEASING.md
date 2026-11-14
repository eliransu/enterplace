# Releasing Gantry

Gantry and Gantry Enterprise ship together under one semantic version, X.Y.Z. A release is a `vX.Y.Z` tag on the same
version in both private repositories, gantry and gantry-enterprise. Nothing is published outside them: the open
source release is a GitHub Release of the private gantry repository, and the image goes to the private package
`ghcr.io/ggantry/gantry-enterprise`.

## Versions

- A patch (0.1.1) fixes without changing behavior anyone relies on. A minor (0.2.0) adds features, and before 1.0 may
  change behavior, said under `### Changed` in the CHANGELOG. Major versions start at 1.0.0.
- Every change a user or operator can see goes under `## [Unreleased]` in the CHANGELOG.md of the repository it
  changes, grouped by feature in plain language, in the same pull request.
- `scripts/version.py` in gantry checks that Cargo.toml, CHANGELOG.md and the Helm chart name one version. CI runs it
  on every push (scripts/ci.sh in gantry, the version job of image.yml here) and strictly on every tag.

## Steps

Run these from a folder that holds both repositories side by side, as `gantry/` and `gantry-enterprise/`, on `main`
with nothing uncommitted.

1. Bump both repositories. The script sets the version in Cargo.toml, Cargo.lock and the Helm chart, and turns
   `## [X.Y.Z] - Unreleased` (or else `## [Unreleased]`) into `## [X.Y.Z] - <today>`:

   ```bash
   gantry/scripts/release.sh bump X.Y.Z
   gantry/scripts/release.sh bump X.Y.Z ../gantry-enterprise
   ```

2. Read both CHANGELOG sections once more, then commit and push to main in each repository, gantry first (or merge a pull request of each):

   ```bash
   git -C gantry commit -am "Release X.Y.Z"
   git -C gantry-enterprise commit -am "Release X.Y.Z"
   git -C gantry push origin main && git -C gantry-enterprise push origin main
   ```

   Wait for CI to pass on both mains.

3. Tag both, gantry first, because the enterprise image build checks out gantry at the same tag:

   ```bash
   git -C gantry tag -a vX.Y.Z -m "Gantry X.Y.Z" && git -C gantry push origin vX.Y.Z
   git -C gantry-enterprise tag -a vX.Y.Z -m "Gantry Enterprise X.Y.Z" && git -C gantry-enterprise push origin vX.Y.Z
   ```

4. Check both GitHub Releases (below) and pull the image by its digest once.

## What each tag starts

| Tag | Workflow | Result |
|---|---|---|
| `vX.Y.Z` in gantry | `.github/workflows/release.yml` | Checks the tag against Cargo.toml and the dated CHANGELOG section. Builds the linux amd64 and arm64 tarballs twice from scratch and fails unless both builds are the same bytes. Runs the rollback check (the previous tag's binary reads this one's data). Writes `SHA256SUMS` and SLSA provenance and signs both with `RELEASE_SIGNING_KEY`'s SSH key, verified against `release/allowed_signers`. Creates the private GitHub Release `vX.Y.Z` with the tarballs, checksums, provenance and signatures, and the CHANGELOG section as its notes. |
| `vX.Y.Z` in gantry-enterprise | `.github/workflows/image.yml` | Checks both repositories against the tag (and fails if gantry has no such tag). Builds the image for amd64 and arm64 from both repositories at `vX.Y.Z`, pushes it to `ghcr.io/ggantry/gantry-enterprise` tagged `X.Y.Z` and the commit SHA, then creates the private GitHub Release `vX.Y.Z` with the CHANGELOG section and the image digest. |

Pushes to main keep publishing `latest` and the commit SHA, as before. Production pins `X.Y.Z` or, better, the digest
from the release notes.

To check a user's download: `scripts/release.sh verify` in gantry, with the release files in `dist/`.

## Dry run

Both workflows run without a tag, publishing nothing:

```bash
gh workflow run release.yml --repo ggantry/gantry --ref <branch>
gh workflow run image.yml --repo ggantry/gantry-enterprise --ref <branch>
```

release.yml dates the CHANGELOG in its runner only, checks it as a tag would be checked, builds, compares, signs and
verifies, and its publish job prints the release it would create instead of creating it. image.yml checks the
versions, builds both architectures and pushes nothing.

## Rolling back

A release is never moved or deleted: a tag and an image tag, once pulled, may be pinned somewhere.

1. Deployments go back to the previous version: `image.tag: X.Y.(Z-1)` in the Helm values, the previous tag or digest in
   the Compose file or Terraform `image` variable, or the previous release's tarball. `scripts/rollback_check.py` runs
   on every release, so the previous binary reads the data of the new one: the audit log stays one verified chain.
2. A release that applied a store migration (its CHANGELOG says so) cannot be rolled back onto that database: an
   older Gantry refuses a newer schema. Restore the backup taken before the upgrade, or stay and fix forward.
3. Mark the bad GitHub Releases in both repositories: edit the title to start with `Withdrawn:` and say why at the top of
   the notes.
4. Fix on main and ship X.Y.(Z+1) with the steps above, saying under `### Fixed` what went wrong.

A tag pushed by mistake, before anyone pulled it: delete the GitHub Release, then the tag (`git push origin
:refs/tags/vX.Y.Z`) in that repository, and delete the image version from the package page on GitHub.
