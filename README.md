<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
  <img src=".github/assets/logo-light.svg" alt="Gantry logo" width="104" height="96">
</picture>

# Gantry

**The open source AI gateway built for governance.**

Every model request gets an identity, a policy decision and a tamper-evident audit record before it reaches a provider.

[![CI](https://github.com/eliransu/gantry/actions/workflows/ci.yml/badge.svg)](https://github.com/eliransu/gantry/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-gantry--docs.enterplace.dev-e3ff45.svg)](https://gantry-docs.enterplace.dev/)

[Documentation](https://gantry-docs.enterplace.dev/) · [Quickstart](https://gantry-docs.enterplace.dev/getting-started/quickstart/) · [Claude Code](https://gantry-docs.enterplace.dev/integrations/claude-code/) · [Policy reference](https://gantry-docs.enterplace.dev/governance/policy/)

</div>

---

Gantry sits between your people, agents and workloads and the model providers they call. Claude Code, Codex, Cursor and any OpenAI or Anthropic SDK point at Gantry instead of the provider. For every request, Gantry:

1. **Identifies** the caller by a personal Gantry key, never a shared provider key.
2. **Decides** by a policy file: which person or team may use which model, within what budget, under which guardrails.
3. **Records** the decision in a hash-chained audit log, before anything is forwarded.
4. **Forwards** the request with the provider's key in place of the caller's.

A request that cannot be recorded is refused. Gantry is one binary (or one container image): policy, keys and audit log are plain files, and Postgres is optional, for teams that share keys and budgets across gateways.

Everything outside `enterprise/` is Apache 2.0. The enterprise features in `enterprise/` are under a commercial license and need a license key; see [License](#license).

## Quickstart

Three steps, about two minutes, no provider key needed:

1. **Install** (macOS and Linux, x86_64 and arm64; the release signature and SHA256 are checked):

   ```bash
   curl -fsSL https://gantry.enterplace.dev/install.sh | sh
   ```

   Or with Docker, which also does step 2: `docker run --pull always -d --name gantry -p 8080:8080 -v gantry-data:/var/lib/gantry ghcr.io/eliransu/gantry`, then `docker logs gantry` for the link.

2. **Start it:**

   ```bash
   gantry start
   ```

3. **Your browser opens:** pick what you want to start with and follow the steps. The first connects a model (paste a provider key, kept sealed) or tries the free demo model; the second sends your first request and shows it arrive.

`gantry start` writes an observe-mode policy (nothing is blocked, every request is recorded), an admin key and a master
key in the current folder, serves on `http://127.0.0.1:8080`, and prints a dashboard link that signs you in once. A
provider key in the environment (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) is picked up too. Every
request is in `gantry-audit.jsonl`; `gantry audit verify gantry-audit.jsonl` proves nothing was changed.

With Postgres, for a team: the [Docker Compose](https://gantry-docs.enterplace.dev/deploy/docker/) guide. From source:
`git clone https://github.com/eliransu/gantry.git && cd gantry && cargo build --release && target/release/gantry start`.

Full walkthrough: [Quickstart](https://gantry-docs.enterplace.dev/getting-started/quickstart/).

## Features

### Governance

- **[Keys per person and workload](https://gantry-docs.enterplace.dev/governance/keys/)**: hashed at rest, with optional expiry, budget, model list and token limit per key.
- **[Self-service keys through SSO](https://gantry-docs.enterplace.dev/governance/single-sign-on/)**: `gantry login` issues a developer an expiring key through your identity provider.
- **[Policy as code](https://gantry-docs.enterplace.dev/governance/policy/)**: first-match rules by team, person or anyone. `gantry check` rejects unknown fields with file, line and fix. Reloads in 2 seconds without a restart.
- **[Budgets and rate limits](https://gantry-docs.enterplace.dev/governance/budgets-and-rate-limits/)**: dollars per organization, team, person, key, end customer, tag or model, reserved at admission. Requests and tokens per minute, hour and day, and requests in flight.
- **[Guardrails](https://gantry-docs.enterplace.dev/governance/guardrails/)**: built-in secret and personal data detectors, thirteen guardrail vendors, and your own services by webhook. Block, mask or record.
- **[Kill switches](https://gantry-docs.enterplace.dev/governance/kill-switches/)**: stop a person, team, key or model at once.
- **[Tamper-evident audit log](https://gantry-docs.enterplace.dev/governance/audit-log/)**: one hash-chained record per request, refusals included, verified with `gantry audit verify`.

### Routing

- **[Providers](https://gantry-docs.enterplace.dev/providers/overview/)**: over 120 provider presets. OpenAI, Anthropic, Azure OpenAI, Amazon Bedrock (every model family), Vertex AI, Gemini, Cohere, IBM watsonx.ai, SageMaker, Replicate, and any OpenAI-compatible server (Groq, Mistral, Together, Fireworks, DeepSeek, OpenRouter, Ollama, vLLM, LM Studio).
- **[Retries and fallbacks](https://gantry-docs.enterplace.dev/routing/retries-and-fallbacks/)** per provider, and **[model aliases](https://gantry-docs.enterplace.dev/routing/aliases/)** over several deployments: round robin, least busy, lowest latency, lowest cost or adaptive, with cooldown.
- **[Translation](https://gantry-docs.enterplace.dev/routing/translation/)**: chat completions to Claude, Claude Code's messages requests to GPT, Gemini or a local model, and Codex's Responses requests to any provider.
- **[Cost on every answer](https://gantry-docs.enterplace.dev/routing/pricing/)** with built-in prices for most models, and an exact or semantic **[cache](https://gantry-docs.enterplace.dev/routing/caching/)** per rule.

### Operations

- **[Admin console](https://gantry-docs.enterplace.dev/operations/console/)** at `/console`: a Start here checklist for the first request, requests, analytics, people and keys, policy and spend, with OIDC or SAML sign-in and roles.
- **[Prometheus metrics](https://gantry-docs.enterplace.dev/operations/observability/)** and audit log shipping with Vector, Fluent Bit or the OpenTelemetry Collector.
- **[Container image and Kubernetes](https://gantry-docs.enterplace.dev/deploy/overview/)**: one non-root image built `FROM scratch` (`ghcr.io/eliransu/gantry`), a Helm chart, Terraform for AWS, Google Cloud and Azure, Docker Compose and Cloudflare.
- **[HTTPS](https://gantry-docs.enterplace.dev/operations/deployment/)** with `--tls-cert` and `--tls-key`.
- **[Migrate from LiteLLM](https://gantry-docs.enterplace.dev/migrate/from-litellm/)**: `gantry import litellm` turns a LiteLLM proxy config into a Gantry policy.

## Integrations

| Tool | Route | Guide |
|---|---|---|
| Claude Code | `/v1/messages` | [docs](https://gantry-docs.enterplace.dev/integrations/claude-code/) |
| Codex CLI | `/v1/responses` | [docs](https://gantry-docs.enterplace.dev/integrations/codex/) |
| Cursor, Continue, Cline, Aider, OpenCode, Gemini CLI, Copilot, Zed and 8 more | `/v1/chat/completions` and others | [docs](https://gantry-docs.enterplace.dev/integrations/coding-tools/) |
| OpenAI and Anthropic SDKs | all | [docs](https://gantry-docs.enterplace.dev/integrations/sdks/) |

## Repository

```text
crates/
  gantry-core      policy, routing, guardrails, audit chain, pricing (library, no HTTP)
  gantry-server    the HTTP gateway (library)
  gantry-console   the admin console assets
  gantry-cli       the gantry binary: start, serve, check, key, audit, kill, usage, budget, login, import, prices
  gantry-bench     overhead benchmark and CI gate
enterprise/        enterprise features (commercial license, see enterprise/LICENSE)
deploy/            Helm chart, Terraform (AWS ECS, GCP Cloud Run, Azure Container Apps), Compose, Cloudflare, MDM
docs/              documentation site (Astro Starlight)
scripts/           CI, release and example checks
```

## Status

Gantry is pre-1.0 (0.1.0, see [CHANGELOG.md](CHANGELOG.md)) and runs as one node on plain files, or as several replicas sharing a Postgres store. See [Project status](https://gantry-docs.enterplace.dev/getting-started/status/) for what is built, what is planned and what has been verified against which services.

## Contributing

```bash
scripts/ci.sh
```

Runs the same checks as CI: format, clippy with warnings as errors, every test, the release build, every policy example through `gantry check`, the overhead bench gate and the docs build. With `GANTRY_TEST_DATABASE_URL`, Chrome and `psql` present it also drives the console's editing pages in a real Chrome (`scripts/console_edit_check.py`), which CI runs as its own `console-edit` job. Conventions are in [AGENTS.md](AGENTS.md).

## License

Gantry is one repository with two licenses, as LiteLLM is:

- Everything outside `enterprise/` is under the [Apache License 2.0](LICENSE).
- `enterprise/` is under the [Gantry Commercial License](enterprise/LICENSE): the source is there to read, and
  running it in production needs a valid Gantry license key.

The open source crates build, test and run without `enterprise/` and never import it. The `gantry` binary in the
image is the enterprise build: with no license key it is the open source gateway, and a key unlocks the enterprise
features. See [License key](https://gantry-docs.enterplace.dev/operations/license/).
