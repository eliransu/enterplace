# Five Steps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach and guide companies through five steps (See, Know, Limit, Protect, Prove) on the landing page, in the docs, in the CLI and in the console, backed by a real observe mode.

**Architecture:** Observe mode and per-feature `shadow_until` live in enterplace-core policy evaluation and are recorded by enterplace-server as `would_refuse`. `enterplace start` is a new CLI subcommand that writes a step-1 policy. The docs get a `start/` section. The console strip computes step state from the store/request index and asks the extension hook for licensed steps; it is built only after its design is approved.

**Tech Stack:** Rust (enterplace-core, enterplace-server, enterplace-cli, enterplace-console), Astro Starlight docs, static landing page.

**Spec:** docs/superpowers/specs/2026-11-14-five-steps-design.md

## Global Constraints

- Step names, exactly and in order: See, Know, Limit, Protect, Prove.
- No em-dashes or en-dashes anywhere. VOICE.md don't-list for all copy. Brand "The Gate".
- Observe mode never forwards a request with a missing, bad or revoked key, or an unknown model. Kill switches always block.
- `unwrap`/`expect` denied, `unsafe` forbidden; fmt, clippy -D warnings, tests pass before each commit. No new dependency.
- Console UI only after an approved design (AGENTS.md).
- Commits as Eliran, no AI attribution lines.

## Review Focus

- A request in observe mode that a budget would refuse is forwarded AND still charged to the budget counter (so the numbers are real when enforcement starts).
- Observe mode with a kill switch on the model: refused with `killed`, never forwarded.
- `shadow_until` in the past: enforced normally; malformed date: `enterplace check` refuses with the field path.
- `enterplace start` run twice in the same folder: refuses to overwrite an existing policy unless `--force`.
- Policy reload switching observe off: the very next request is enforced.

---

### Task 1: Observe mode

**Files:**
- Modify: `crates/enterplace-core/src/policy.rs` (Policy: `pub mode: Mode` with `enum Mode { Enforce, Observe }`, default Enforce)
- Modify: `crates/enterplace-core/src/config.rs` (parse top-level `mode: observe|enforce`, warning from `enterplace check` when observe)
- Modify: `crates/enterplace-server/src/lib.rs`, `spend.rs` (where a policy refusal is returned: in observe, record a decision record with `outcome: "would_refuse"` and the refusal `code`, then forward)
- Modify: `crates/enterplace-console/src/html.rs` (banner "Observe mode: nothing is blocked" using existing banner component)
- Test: `crates/enterplace-server/tests/observe.rs`

**Interfaces:**
- Produces: `Policy::observing(&self, feature: Feature, now) -> bool` where `enum Feature { Rule, Budget, Limit, Guardrail, Region }`; Task 2 extends it with per-feature shadow dates.

- [ ] Write tests: `observe_forwards_what_a_budget_would_refuse_and_records_would_refuse` (budget 0.01, two calls, both 200, second record outcome `would_refuse` code `budget_exceeded`, spend counter includes both); `observe_still_refuses_missing_key` (401 `no_key`); `observe_still_refuses_unknown_model`; `observe_still_honours_kill_switch` (`killed`, upstream mock sees no call); `reload_to_enforce_takes_effect_on_next_request`; `check_warns_on_observe`.
- [ ] Run, see them fail. Implement. Run `cargo test -p enterplace-server --test observe` and the whole workspace. Docs: `governance/policy.mdx` mode section, `reference/audit-records.mdx` `would_refuse`. Commit.

### Task 2: `shadow_until` on rules, budgets and limits

**Files:**
- Modify: `crates/enterplace-core/src/policy.rs`, `config.rs` (accept `shadow_until` on rules, on each budget, on `limits:` entries; same date format and checks as guardrails, reuse `guard.rs` parsing)
- Test: add to `crates/enterplace-server/tests/observe.rs`

**Interfaces:**
- Consumes: `Policy::observing` from Task 1; returns true when `mode == Observe` or the matching feature's `shadow_until` is in the future.

- [ ] Tests: `shadowed_budget_forwards_and_records_while_other_budgets_enforce`; `past_shadow_until_enforces`; `malformed_shadow_until_is_refused_by_check_with_path` (error names e.g. `rules[0].budget.shadow_until`). Implement, run workspace tests, update budgets docs, commit.

### Task 3: `enterplace start`

**Files:**
- Modify: `crates/enterplace-cli/src/lib.rs` (new subcommand `start`)
- Create: `crates/enterplace-cli/src/start.rs`
- Test: `crates/enterplace-cli/tests/cli.rs`

**Interfaces:**
- Produces: `enterplace start [--dir <path>] [--providers openai,anthropic,...] [--yes] [--force] [--no-serve]`.

- [ ] Tests: `start_writes_an_observe_policy_from_env_keys` (OPENAI_API_KEY and ANTHROPIC_API_KEY set, `--yes --no-serve`: writes `enterplace.policy.yaml` with `mode: observe`, one allow-all rule, providers with `key_env`, a keys file with one admin key printed once; `enterplace check` passes on it); `start_refuses_to_overwrite_without_force`; `start_prints_tool_settings` (output names Claude Code `ANTHROPIC_BASE_URL`, Codex, Cursor with the local URL); `start_without_any_provider_key_says_which_env_to_set`.
- [ ] Implement (interactive prompts only when stdin is a TTY and `--yes` absent; reuse the existing policy writer/check code). Run CLI tests and workspace. Docs: `reference/cli.mdx`. Commit.

### Task 4: Docs "Start here"

**Files:**
- Create: `docs/src/content/docs/start/why.mdx`, `step-1-see.mdx` ... `step-5-prove.mdx`, `plan.mdx`
- Modify: `docs/astro.config.mjs` (first sidebar group "Start here": why, five steps, plan, then quickstart, how-it-works, status, changelog; Getting started group removed), `docs/src/content/docs/index.mdx` (lead with the ladder)

- [ ] Each step page: what you get; the one change (policy lines or command, using `mode: observe` / `shadow_until` / `enterplace start` from Tasks 1 to 3); how to check it in the console; "when you're ready" link to the next step. Step 5 marks SIEM export, retention, legal hold as Enterprise. Step 1 promises tools, models and cost per key, not people.
- [ ] Every policy snippet is added to the examples `scripts/check_examples.py` checks. `npm run build` passes, no broken links. Commit.

### Task 5: Console "Your setup" design

**Files:** none in the repo until approved.

- [ ] Produce the design for the strip and next-step panel with the design system (https://claude.ai/artifact/Ub4EmnexinkC5F67McBUvC) as an artifact for Eliran's sign-off: states done/current/ahead, the Claude Team track, the Enterprise marker on Prove, the "Show the change" action.

### Task 6: Console "Your setup" build (after Task 5 approval)

**Files:**
- Create: `crates/enterplace-console/src/setup.rs`
- Modify: `crates/enterplace-console/src/lib.rs`, `pages.rs`, `crates/enterplace-server/src/lib.rs` (`Extension::setup_steps` hook returning licensed step state)
- Test: `crates/enterplace-console/tests/setup.rs`

**Interfaces:**
- Produces: `fn steps(state: &SetupFacts) -> [Step; 5]` with `struct Step { name: &'static str, status: Status, next: Option<Action> }`, `enum Status { Done, Current, Ahead, NotApplicable }`.

- [ ] Tests per the spec's progress rules (See done with requests in 7 days; Know done with more than one person and no shared key, or SSO/JWT; Limit done when every team with traffic has a budget; Protect current with a shadow guardrail, done when enforced; Prove done when chain verifies and audit kept outside the container, Enterprise parts marked); Claude Team track marks Limit and Protect NotApplicable. Implement, screenshot-compare with the design, commit.

### Task 7: Landing page ladder

Covered by the running landing rework (problem section plus the five steps). Verify the names and order match Global Constraints after it lands.
