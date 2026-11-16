# Architecture

Gantry sits between callers (coding agents, apps, MCP clients) and model providers. Every request goes through the
same path:

```
caller ──> identify ──> policy ──> guardrails ──> route ──> provider
              │            │            │            │          │
              └────────────┴────────────┴─── audit record ──────┘
```

1. **Identify**: which person or workload is asking: a Gantry key, a person token, a JWT, or a passed-through
   subscription login.
2. **Policy**: may they use this model, within which budget and rate limit (`gantry.policy.yaml`).
3. **Guardrails**: secrets and personal data in the prompt are found and blocked, masked or recorded.
4. **Route**: pick the deployment, translate the request to the provider's format if needed, retry or fall back.
5. **Audit**: one hash-chained line per request, so a changed or deleted record is detected by `gantry audit verify`.

## Crates

| Crate | What it holds | Start reading at |
|---|---|---|
| `crates/gantry-core` | Types, policy, routing, guardrails, format translation, audit. A library with no HTTP server. | `policy.rs`, `guard.rs`, `translate.rs`, `audit.rs` |
| `crates/gantry-server` | The HTTP server (axum): the OpenAI and Anthropic compatible endpoints, admin API, MCP gateway, metrics. | `lib.rs`, `mcp.rs`, `stages.rs` |
| `crates/gantry-console` | The admin console: server-rendered HTML, one CSS and one JS file in `assets/`. | `lib.rs`, `pages.rs`, `start.rs` |
| `crates/gantry-cli` | The `gantry` binary: `start`, `stop`, `key`, `audit`, `budget` and the rest. Server and CLI in one. | `lib.rs`, `start.rs` |
| `crates/gantry-bench` | The overhead benchmark and the CI gate that fails a change that makes Gantry slower. | `src/` |
| `enterprise/` | Paid features behind a license key (commercial license). The open crates never import it; it plugs in through their extension hooks. | `docs/porting.md` |

## Where a few things live

| You want to change | Look in |
|---|---|
| A provider (URL, auth, quirks) | `gantry-core/src/catalog.rs`, plus `vendors.rs` and the format files (`gemini.rs`, `cohere.rs`, `converse.rs` and others) |
| OpenAI and Anthropic format translation | `gantry-core/src/translate.rs` |
| What a policy file can say | `gantry-core/src/policy.rs` and `config.rs`; docs in `docs/src/content/docs/governance/policy.mdx` |
| Secret and personal data detectors | `gantry-core/src/guard.rs`, `gitleaks.rs`; test corpus in `gantry-core/tests/corpus/` |
| Shared state across replicas (Postgres) | `gantry-core/src/store.rs`, `gantry-server/src/store.rs` |
| The first-run checklist | `gantry-console/src/start.rs` |
| An integration guide | `docs/src/content/docs/integrations/` |

## State

A single gateway keeps everything in files beside its policy: keys, the audit log, spend. Several replicas share
keys, spend, rate limits and kill switches through Postgres. The policy stays a file, reviewed in Git like code.
