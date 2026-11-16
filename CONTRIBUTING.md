# Contributing to Gantry

Thanks for helping. Gantry is a self-hosted AI gateway in Rust. Small fixes are as welcome as features: a clearer
error message, a missing test, an integration guide for a tool you use.

## Start in five minutes

You need Rust (the version in `rust-toolchain.toml` installs itself through rustup) and Git.

```sh
git clone https://github.com/eliransu/gantry.git && cd gantry
cargo run -p gantry-cli -- start
```

That builds the `gantry` binary and starts a gateway in the current folder with a demo model, so you can send a
request without any provider key. The console opens at the link it prints.

Before you open a pull request, run the checks CI runs:

```sh
scripts/ci.sh --no-bench
```

It runs `cargo fmt`, `cargo clippy -D warnings` and every test. Tests that need Postgres skip themselves unless
`GANTRY_TEST_DATABASE_URL` is set.

## Find something to work on

- Issues labeled [good first issue](https://github.com/eliransu/gantry/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
  name the files to change and the test that proves it works. Comment on one to take it.
- A tool you use is missing from `docs/src/content/docs/integrations/`? A guide for it is a great first PR.
- Found a bug? Open an issue with the request you sent and what came back. Remove keys and personal data first.

[ARCHITECTURE.md](ARCHITECTURE.md) shows where each part of the gateway lives.

## How we work

- **Test first.** Write the test that fails, then the code that makes it pass.
- **No `unwrap`, `expect` or `unsafe`.** The lints deny them, tests included. Return errors instead.
- **Error messages name the cause and the fix,** for example "the policy names provider `azure`, which has no `url`:
  add one".
- **Unknown provider parameters pass through or return a 400.** Gantry never drops or rewrites them silently.
- **New dependencies need a reason.** Say in one line in the PR why the standard library or an existing dependency
  does not cover it. `cargo deny check` must pass.
- **Comments explain why, not what.**
- **Console UI** uses only components from the Gantry design system. For a new screen, open an issue first so the
  design can be agreed.
- **Clean room.** Do not copy source code from other gateways (LiteLLM, Bifrost and others). Provider API docs and
  their public docs are fine.

## Pull requests

- One change per PR, with a title that says what changes for a user.
- Add a line under `## [Unreleased]` in `CHANGELOG.md` if a user or operator can see the change.
- Docs live in `docs/src/content/docs` (Astro Starlight). `cd docs && npm install && npm run dev` previews them.

## License

Everything outside `enterprise/` is MIT, and your contribution there is under MIT too. `enterprise/` is under the
Gantry commercial license (`enterprise/LICENSE`); patches to it are welcome under the same terms.
