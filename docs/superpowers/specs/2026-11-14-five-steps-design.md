# Five steps: teach and guide companies from "confused" to "governed"

Date: 2026-11-14. Status: draft for Eliran's approval.

## Intent

Companies are confused about AI: which tools their people use, what it costs, what leaves the building, and what to do first. Gantry should teach them and walk with them, from why they need a gateway, to a first result in minutes, to full control, one simple step at a time. Keeping it simple is the point; a step that needs a meeting to understand has failed.

Two readers, both served:
- **The decider** (CISO, head of platform, CTO at a smaller company). Needs the why and a plan they can say yes to.
- **The builder** (platform or security engineer). Needs the next concrete step, inside the product, from where they are now.

## The ladder (shared everywhere)

| Step | Name | What they do | What they get | Gantry pieces |
|---|---|---|---|---|
| 1 | See | Run Gantry, point tools at it, one rule that allows everyone. Nothing is blocked. Claude subscription teams use the watch setup instead. | Which tools and models are in use and what they cost, per key, from day one | quickstart, coding-tool guides, request log, analytics, `gantry audit coverage`, Claude Team watch |
| 2 | Know | A key per person and per team, or SSO/JWT so people sign in as themselves | Every request has a name and a team on it | keys, SSO, SCIM, JWT, teams |
| 3 | Limit | Budgets per team or person, rate limits, kill switches | No surprise bills, and a stop button | budgets, limits, kill switches, alerts on spend |
| 4 | Protect | Guardrails on prompts and answers in shadow mode first, then enforced; MCP tools behind the gateway | Secrets and personal data stay in; risky tools need approval | guardrails, shadow mode, backtest, MCP gateway |
| 5 | Prove | Audit export to the SIEM, retention, legal hold, reports | Evidence for the auditor and the board | audit chain, SIEM export, retention, coverage, policy versions and approval |

Each step is one change on top of the last, shown as the policy lines it adds. No step requires the next one.

## Goals

1. A decider understands in 2 minutes why the company needs this and what step 1 costs them (one container, nothing blocked).
2. A builder gets from nothing to step 1 with real traffic in under 15 minutes, following one page.
3. Inside the console, the builder always sees which step they are on and the single next action, computed from the gateway's real state.
4. The same five names, in the same order, on the landing page, in the docs and in the console.

## Non-goals

- No sales funnel features (lead forms, gated PDFs, email capture).
- No in-product tours that pop over the UI, no confetti, no gamified badges.
- No new reference docs; the reference stays as it is and the steps link into it.

## Anti-goals (failure even if it works)

- Fear-selling: scare statistics or invented incidents. Every claim about risk is a plain example, never a fabricated number.
- Jargon on the first screen of any step ("egress governance", "policy enforcement point").
- A step that asks for more than one decision.
- Steps that disagree with what the product actually does.

## Constraints

- Console UI needs an approved Claude Design design before any code (AGENTS.md); content ships first, the console part after the design.
- Voice: Eliran's VOICE.md don't-list, no em or en dashes, brand "The Gate" (ink, paper, lime, flame; Familjen Grotesk, Fragment Mono).
- Lasso only ever appears as one guardrail vendor among several.
- Clean room on competitors; any comparison is from public docs only.

## Approaches considered

- **A. Content first:** a Start here path on the site and docs, console unchanged. Fast, but the builder is alone once inside.
- **B. Console first:** a next-step panel from real state, thin content. Guides well, but the decider never gets the why.
- **C. One ladder used everywhere (picked by Eliran):** the landing page leads with the problem and the ladder, the docs get a Start here section with one page per step, and the console shows "step N of 5, next: ..." from real state, linking to the same pages. Picked because decider and builder then talk about the same five steps.

## What gets built

### 1. Landing page (site/public)
- A new first section after the hero: the problem in plain words (people already use AI tools, nobody can say who, how much, or what was sent), then the five steps as a horizontal ladder, each with one line and a link to its docs page.
- Hero copy shifts to the outcome ("Know who uses AI, cap what it costs, keep secrets in. One step at a time.") while keeping the current design system.
- Existing Controls section stays below, as the detail.

### 2. Docs: "Start here" section (docs/src/content/docs/start/)
- `why.mdx`: why a company needs a gateway, for the decider. One page, five short questions (who uses what, what it costs, what leaves, can you stop it, can you prove it), each answered by a step.
- `step-1-see.mdx` to `step-5-prove.mdx`: each page has the same shape: what you get, the one change (policy lines or a command), how to check it worked (what to look at in the console), and "when you're ready" pointing to the next step. Each fits on one screen before its optional "more" part.
- `plan.mdx`: a one-page rollout plan a decider can forward (week 1 see, week 2 know, and so on, phrased as order not dates).
- Sidebar: "Start here" becomes the first group; the current Getting started group merges into it (quickstart becomes step 1's page or is linked from it).
- The docs home (`index.mdx`) leads with the ladder.

### 3. Step 1 needs a true "nothing blocked" mode
Today step 1 relies on a rule that allows everyone. Add `mode: observe` (see builder check answers 1 and 2 for its exact limits) at the policy top level: every request is forwarded, and every decision that would have refused is recorded as `would_refuse` with its code, in the same audit chain. Budgets, limits, guardrails and kill switches compute and record but do not block. Kill switches still block (a stop button must always work). `gantry check` warns when observe mode is on. The console shows an "Observe mode: nothing is blocked" banner. This lets a company turn on steps 2 to 4 safely and see what would happen before enforcing, which is the main way to keep each step low-risk.

### 4. `gantry start`: a guided first run (CLI)
An interactive command that writes a step-1 policy (asks which providers they use, reads keys from env, writes `gantry.policy.yaml` with observe mode and one allow-all rule), prints the exact settings for the coding tools it detects on the machine, and starts the gateway. Non-interactive flags for CI. Replaces the copy-paste part of the quickstart.

### 5. Console: "Your setup" (after design approval)
- A strip on the console home: five steps, each done, current or ahead, computed from state:
  - See: done when the gateway has served requests in the last 7 days.
  - Know: done when more than one person or team appears and requests carry no shared key (or SSO/JWT is configured).
  - Limit: done when at least one budget applies to every team that has traffic, and a kill switch has been tested or exists.
  - Protect: done when at least one guardrail runs on requests (shadow counts as started, enforced as done), and MCP servers, if any, go through the gateway.
  - Prove: done when an audit export or retention is configured and the chain verifies.
- Under the current step: one sentence of why, the single next action, and a link to its Start here page. Where the action is a policy change, a "Show the change" button opens the policy editor (console-edit) with the lines pre-filled as a draft, never applied without the normal save and approval.
- Facts that teach, from the real data: "14 people used 6 models this week, $212, no budgets yet." Plain numbers, no scare framing.
- Design: request a Claude Design design for this strip and panel first; screenshots compared in CI per AGENTS.md.

## Decided by Eliran
- Serve both readers; decider content and builder guidance.
- Approach C, one ladder everywhere.

## Answers to the builder check (my calls)
1. Observe mode never opens the gateway: a missing or bad key, a revoked key and an unknown model are still refused (there is nowhere to forward an unknown model, and an open gateway would spend the company's provider keys). Observe only softens policy decisions: rule matches, budgets, rate and parallel limits, guardrails, regions. Kill switches always block.
2. Both levels: top-level `mode: observe` for a first rollout, and the existing per-feature `shadow_until` (already on guardrails) extended to rules, budgets and limits, so a company that enforces budgets can trial guardrails alone. Step pages say "shadow this one feature" from step 3 on.
3. After the repo fold, the console strip lives in the open console and asks the extension for extra step state through a hook. The open edition can complete See, Know, Limit and Protect. Prove shows its licensed parts (SIEM export, retention, legal hold) marked "Enterprise", consistent with the paid line in Q2; in the open edition Prove is done when the audit chain verifies and the audit file is kept outside the container.
4. Step 1 promises tools, models and cost, not people. Names arrive in step 2. Step 1 still shows one line per key and per tool (user agent), so the jump to step 2 is obvious.
5. Claude Team watch companies get a track of their own in the strip: See and Know apply from the OpenTelemetry data, Limit and Protect show "needs API traffic through Gantry" with a link explaining why, Prove applies.

## My calls (correct any)
- The five names: See, Know, Limit, Protect, Prove.
- Observe mode as a real policy mode, with kill switches still enforced.
- `gantry start` as the guided first run.
- Docs section at `/start/`, absorbing Getting started.
- Progress rules as listed under 5.

## Left to the builder
- Exact copy within the voice rules, page layouts within the design system, how state is computed efficiently (reuse analytics and the request index), test shapes.
