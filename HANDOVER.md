# Enterplace handover (2026-11-26)

Repository: https://github.com/eliransu/enterplace (public). Read `AGENTS.md` first: its rules are binding (acceptance
test first, no em or en dashes anywhere, no AI attribution in commits, `cargo fmt`, `cargo clippy --all-targets -- -D
warnings` and `cargo test` before a commit, error messages name cause and fix, paid features only in `enterprise/`,
console UI in `console-ui/` with design tokens, `npm run build` in `console-ui/` and commit `crates/enterplace-console/app/`
with the source). Release steps: `RELEASING.md`.

Never put a secret in chat, a file or a command line the owner can see. Never commit deployment details (hostname,
account) to the repository: it is public.

## State

- `main` is at `ca1d6cc` "Release 0.3.0" and tag `v0.3.0` is pushed. It contains:
  - Console: searchable pickers with Create (team, person, app, tag) in the rule, limit and kill switch forms; a new
    person or app opens Issue a key in place and comes back with it picked (`console-ui/src/components/team-picker.tsx`).
  - Console: sidebar grouped by use case (Coding agents, Apps and agents, Security, Activity, Settings); Guardrails page
    at `/guardrails`; Policy file and Versions under Settings (`console-ui/src/pages/index.ts`).
  - Console: "Copy for your agent" on every create flow: new key, person token and service key dialogs (built in the
    browser, `console-ui/src/lib/agent.ts`), and Rules, Aliases and MCP servers (`crates/enterplace-console/src/start.rs`
    `rule_prompt`, `alias_prompt`, `mcp_prompt`).
  - Console: Add a provider with models as chips, one key field, More options, pinned dialog buttons
    (`console-ui/src/components/chips-input.tsx`, `console-ui/src/pages/Providers.tsx`, `components/ui/dialog.tsx`).
  - Coding agent controls: `coding_agents: { bypass_permissions, auto_mode, browser }` (allow or block, org wide and per
    rule). Device layer writes Claude Code managed settings; gateway refuses browser tools with `browser_not_allowed`.
    Docs: `docs/src/content/docs/governance/coding-agent-controls.mdx`.
- CI on `main` for `ca1d6cc`: `browser` FAILED (see task 1). Others were passing or still running at handover.
- The `v0.3.0` workflows (`image`, `release`) were still running at handover.

## Branches

| Branch                  | State                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `console-pickers-nav`   | Merged into main.                                                                             |
| `coding-agent-controls` | Merged into main.                                                                             |
| `new-caller-discovery`  | `7204b01` is a working commit, then `3a99909` WIP (unfinished, untested). Based on `8061ffd`. |
| `console-updates`       | `1be46ed` WIP only (unfinished, untested). Based on `8061ffd`.                                |

## Tasks, in order

### 1. Fix the browser check on main

`python3 scripts/browser_check.py --chrome "$(command -v google-chrome)"` fails: "waited 10 s for the new key; the page
is at /console/app/#/people?issue=1". Cause is most likely the new EntityPicker in the Issue a key dialog: the team field
now accepts a team only when it is picked from the list or created with the "Create team X" row, and the script types
into it the old way. Fix the script to pick or create the team (do not weaken the check), or fix the picker if it is the
picker. Also check the script for the renamed sidebar labels ("People" is now "Users", "Teams" is "Groups"). Push to main
and wait for CI green.

### 2. Finish `new-caller-discovery`

The owner's request: the organization decides what happens with something new. Modes: allow and log (pass, record,
flag as discovered and notify), hold for approval (refuse the first request with a refusal that names the console page,
list it as pending), block (refuse, list, admin can allow). A "New and pending" view with Allow and Block buttons, taking
effect within 2 seconds without YAML; a badge and an Overview item; the existing alerting channel. What counts as new:
at least a key, app or agent identity seen for the first time, and a model no provider serves (offer Add a provider as the
fix). Must work on the Cloudflare Durable Object store and Postgres alike (`deploy/cloudflare/src/store.ts` holds the
Cloudflare store's migrations). Docs page and refusal codes. The owner's trigger: they made a service key, sent a request,
and were refused with no way to allow it.

Start by reading `git log -p 8061ffd..new-caller-discovery`: commit `7204b01` holds the server side, the WIP commit the
console page (`console-ui/src/pages/NewCallers.tsx`), Overview and badge. Finish, test end to end in a browser (build
`cargo build -p enterplace-cli`, run `target/debug/enterplace start --dir <temp> --listen 127.0.0.1:<port> --no-open`,
sign in with the printed admin key, make a service key, send a request, check each mode), rebase on main, merge.

### 3. Finish `console-updates`

The owner's request: when a newer release exists, an admin sees it in the console and updates from there, rolling
through the gateways with no downtime, with rollback if health fails. Per target: Cloudflare (roll the container
application image through the Cloudflare API with a narrowly scoped API token kept as a Workers secret, if sound), Docker
Compose (zero downtime only with 2 or more replicas, say so otherwise), Kubernetes (rolling update with a service account
limited to its own Deployment, or the exact `helm upgrade` command), others (exact command plus "Copy for your agent").
Verify releases the way `docs/.../operations/verify-release` does. Every update and rollback is an audit admin record.

The WIP commit `1be46ed` has `crates/enterplace-server/src/update.rs`, `crates/enterplace-cli/tests/update.rs`, Health page
changes (`console-ui/src/pages/Deployments.tsx`) and `docs/src/content/docs/operations/updates.mdx`. Read it, finish,
test (fake the release feed; never call a real registry or Cloudflare in tests), rebase on main, merge.

### 4. Release 0.4.0

Once 2 and 3 are merged and CI is green: `scripts/release.sh bump 0.4.0`, CHANGELOG entries in plain language, commit
"Release 0.4.0", push main, wait for CI, tag `v0.4.0`, push the tag, wait for the `image` workflow, take the image digest
from the GitHub Release.

### 5. Update the owner's Cloudflare gateway

The owner runs Enterplace on Cloudflare from the template in `deploy/cloudflare`, kept on their own machine (not in the
repository), with these edits: Worker `enterplace`, R2 bucket `enterplace-audit`, `GATEWAYS` `"2"`, a custom domain route
(ask the owner for the hostname), and this policy (the live policy is kept in the store, so this file only seeded
version 1):

```yaml
version: 1
providers:
  - name: claude-subscriptions
    kind: anthropic
    url: https://api.anthropic.com
    auth: passthrough
    identity: required
    models: ["claude-*"]
rules:
  - name: everyone
    principals: { any: true }
    models: ["*"]
audit: { path: /var/lib/enterplace/enterplace-audit.jsonl }
store: { cloudflare: true, policy_from: store }
```

The update is one line: `ENTERPLACE_IMAGE` in `image_vars` of `wrangler.jsonc` set to
`ghcr.io/eliransu/enterplace@sha256:<digest of the release>`, then `npx wrangler deploy`. The template did not change
between 0.2.0 and 0.3.0; compare `deploy/cloudflare` of the new tag with the owner's copy before deploying a later one.
The containers roll one instance at a time (max_instances 4, GATEWAYS 2), so there is no downtime. Then check
`curl -s https://<hostname>/healthz` answers `"status":"ok"` on repeated calls, and the console shows the new version.

`wrangler deploy` needs the owner's Cloudflare login. A cloud session has none: ask the owner to run the deploy on their
machine (`cd <their enterplace-cloudflare folder> && npx wrangler deploy` after the one-line edit), or to provide a
Cloudflare API token as an environment variable of the session themselves. Never ask for the token in chat.

## Open questions for the owner

Ask the owner for: the gateway hostname, whether their app providers (for example OpenRouter) are added in the console yet, and anything listed in their own copy of this handover.
