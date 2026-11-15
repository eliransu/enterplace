# Conventions for agents working in this repository

This is Gantry, an AI gateway: the open source crates (Apache 2.0) and, in `enterprise/`, the commercial features under their own license. The full plan is kept outside this repository.

## Rules

1. One slice per session, branch and pull request. A slice has a spec in the plan's specs folder, reviewed by product before work starts, and may touch several work packages. It is done only when its acceptance checks pass in CI.
2. Write the acceptance test first, then the code.
3. Clean room: do not read or copy source code from Bifrost or LiteLLM. Use provider API documentation and the public documentation of those projects only. The LiteLLM price map is the one exception (MIT data, attributed).
4. No new dependency without a one-line justification in the pull request. Standard library first. `cargo deny check` must pass.
5. Never weaken a fail-closed test, a policy test or the bench gate to make a package pass. Stop and report instead.
6. License checks live only inside `enterprise/`. Nothing outside `enterprise/` imports it: `gantry-core`, `gantry-server`, `gantry-console` and `gantry-cli` build and test alone (`cargo test -p gantry-core`) and hold no license code. Enterprise features plug in through the extension hooks the open crates define (`enterprise/docs/porting.md`). `enterprise/` is under its own commercial license (`enterprise/LICENSE`); everything else is Apache 2.0. Never move enterprise code out of `enterprise/`.
7. Unknown provider parameters pass through or return a 400. They are never dropped or rewritten silently.
8. Error messages name the cause and the fix.
9. Product work packages (marked P in the plan) go in `enterprise/`.

## UI

- No UI code without an approved design in Claude Design behind it. Every component comes from the design system's component inventory.
- No Tailwind, no stock component library look, no color, radius, shadow, spacing or font size that is not a design token.
- Built components are compared with their design by screenshot in CI.

## Teams

Each session works as one team: product, design, engineering or DevOps. A package needs its product spec before work starts, and its sign-offs before it merges.

## Code

- `unsafe` is forbidden. `unwrap` and `expect` are denied by lint, tests included. Return errors.
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass before a commit.
- Comments explain why, not what.
- No em-dashes or en-dashes anywhere: code, comments, docs, commit messages.
- Commit messages carry no AI attribution lines.

## Layout

- `crates/gantry-core`: types, routing, policy, hooks. Embeddable as a library. No HTTP server code.
- `crates/gantry-server`: the HTTP server, as a library.
- `crates/gantry-console`: the admin console.
- `crates/gantry-cli`: the open source `gantry` binary. Server and command line in one. `cargo install` builds it.
- `crates/gantry-bench`: the overhead benchmark and the CI bench gate.
- `enterprise/`: the `gantry-enterprise` crate (commercial license). Its binary is the `gantry` shipped in the image: every open source command plus `license`, `node` and `device`; with no license key it behaves as the open source edition, a valid key unlocks the paid features (30-day grace after expiry). Test it with `cargo test -p gantry-enterprise` and `--all-features` (`issuer`, staff only).
- `deploy/`: Helm chart, Terraform modules (aws-ecs, gcp-cloud-run, azure-container-apps), Cloudflare template, Compose test, MDM files. The image carries helm, terraform and cloudflare under `/deploy`.
- `Dockerfile`: the one image, `ghcr.io/eliransu/gantry`. Releases: `RELEASING.md`.
- `docs/`, `site/`, `scripts/`: the docs site, the landing page, CI and release scripts.
