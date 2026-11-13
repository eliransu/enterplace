# Conventions for agents working in this repository

This is the open source edition of Gantry, an AI gateway. The commercial product lives in a separate private repository and depends on these crates. The full plan is kept outside this repository.

## Rules

1. One slice per session, branch and pull request. A slice has a spec in the plan's specs folder, reviewed by product before work starts, and may touch several work packages. It is done only when its acceptance checks pass in CI.
2. Write the acceptance test first, then the code.
3. Clean room: do not read or copy source code from Bifrost or LiteLLM. Use provider API documentation and the public documentation of those projects only. The LiteLLM price map is the one exception (MIT data, attributed).
4. No new dependency without a one-line justification in the pull request. Standard library first. `cargo deny check` must pass.
5. Never weaken a fail-closed test, a policy test or the bench gate to make a package pass. Stop and report instead.
6. This repository holds no enterprise code and no license checks. Product features plug in through traits defined here.
7. Unknown provider parameters pass through or return a 400. They are never dropped or rewritten silently.
8. Error messages name the cause and the fix.

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
- `crates/gantry-cli`: the `gantry` binary. Server and command line in one.
