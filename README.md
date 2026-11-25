<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
  <img src=".github/assets/logo-light.svg" alt="Enterplace logo" width="104" height="96">
</picture>

# Enterplace

**The open source AI gateway built for governance.**

Every model request gets an identity, a policy decision and a tamper-evident audit record before it reaches a provider.

[![CI](https://github.com/eliransu/enterplace/actions/workflows/ci.yml/badge.svg)](https://github.com/eliransu/enterplace/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-docs.enterplace.dev-e3ff45.svg)](https://docs.enterplace.dev/)
[![Good first issues](https://img.shields.io/github/issues/eliransu/enterplace/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/eliransu/enterplace/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
[![Discussions](https://img.shields.io/github/discussions/eliransu/enterplace?label=discussions)](https://github.com/eliransu/enterplace/discussions)

[Documentation](https://docs.enterplace.dev/) · [Quickstart](https://docs.enterplace.dev/getting-started/quickstart/) · [Coding tools](https://docs.enterplace.dev/integrations/coding-tools/) · [Policy reference](https://docs.enterplace.dev/governance/policy/)

</div>

---

Enterplace sits between your people, agents and workloads and the model providers they call. Coding agents (Codex, Claude Code, Cursor, Gemini CLI, Copilot), internal apps, agents, MCP clients and any OpenAI, Anthropic or Gemini SDK point at Enterplace instead of the provider, and it sends their requests on to OpenAI, Anthropic, Gemini, Vertex AI, Bedrock, Azure OpenAI, Mistral or local models on Ollama, vLLM and LM Studio. For every request, Enterplace:

1. **Identifies** the caller by a personal Enterplace key, never a shared provider key.
2. **Decides** by a policy file: which person or team may use which model, within what budget, under which guardrails.
3. **Records** the decision in a hash-chained audit log, before anything is forwarded.
4. **Forwards** the request with the provider's key in place of the caller's.

A request that cannot be recorded is refused. Enterplace is one binary (or one container image): policy, keys and audit log are plain files, and Postgres is optional, for teams that share keys and budgets across gateways.

Everything outside `enterprise/` is MIT. The enterprise features in `enterprise/` are under a commercial license and need a license key; see [License](#license).

## Quickstart

Three steps, about two minutes, no provider key needed:

1. **Install** (macOS and Linux, x86_64 and arm64; the release signature and SHA256 are checked):

   ```bash
   curl -fsSL https://enterplace.dev/install.sh | sh
   ```

   Or with Docker, which also does step 2: `docker run --pull always -d --name enterplace -p 8080:8080 -v enterplace-data:/var/lib/enterplace ghcr.io/eliransu/enterplace`, then `docker logs enterplace` for the link.

2. **Start it:**

   ```bash
   enterplace start
   ```

3. **Your browser opens:** pick what you want to start with and follow the steps. The first connects a model (paste a provider key, kept sealed) or tries the free demo model; the second sends your first request and shows it arrive.

`enterplace start` writes an observe-mode policy (nothing is blocked, every request is recorded), an admin key and a master
key in the current folder, serves on `http://127.0.0.1:8080`, and prints a dashboard link that signs you in once. A
provider key in the environment (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) is picked up too. Every
request is in `enterplace-audit.jsonl`; `enterplace audit verify enterplace-audit.jsonl` proves nothing was changed.

With Postgres, for a team: the [Docker Compose](https://docs.enterplace.dev/deploy/docker/) guide. From source:
`git clone https://github.com/eliransu/enterplace.git && cd enterplace && cargo build --release && target/release/enterplace start`.

Full walkthrough: [Quickstart](https://docs.enterplace.dev/getting-started/quickstart/).

## Features

### Governance

- **[Keys per person and workload](https://docs.enterplace.dev/governance/keys/)**: hashed at rest, with optional expiry, budget, model list and token limit per key.
- **[Self-service keys through SSO](https://docs.enterplace.dev/governance/single-sign-on/)**: `enterplace login` issues a developer an expiring key through your identity provider.
- **[Policy as code](https://docs.enterplace.dev/governance/policy/)**: first-match rules by team, person or anyone. `enterplace check` rejects unknown fields with file, line and fix. Reloads in 2 seconds without a restart.
- **[Budgets and rate limits](https://docs.enterplace.dev/governance/budgets-and-rate-limits/)**: dollars per organization, team, person, key, end customer, tag or model, reserved at admission. Requests and tokens per minute, hour and day, and requests in flight.
- **[Guardrails](https://docs.enterplace.dev/governance/guardrails/)**: built-in secret and personal data detectors, thirteen guardrail vendors, and your own services by webhook. Block, mask or record.
- **[Kill switches](https://docs.enterplace.dev/governance/kill-switches/)**: stop a person, team, key or model at once.
- **[Tamper-evident audit log](https://docs.enterplace.dev/governance/audit-log/)**: one hash-chained record per request, refusals included, verified with `enterplace audit verify`.

### Routing

- **[Providers](https://docs.enterplace.dev/providers/overview/)**: over 120 provider presets. OpenAI, Anthropic, Azure OpenAI, Amazon Bedrock (every model family), Vertex AI, Gemini, Cohere, IBM watsonx.ai, SageMaker, Replicate, and any OpenAI-compatible server (Groq, Mistral, Together, Fireworks, DeepSeek, OpenRouter, Ollama, vLLM, LM Studio).
- **[Retries and fallbacks](https://docs.enterplace.dev/routing/retries-and-fallbacks/)** per provider, and **[model aliases](https://docs.enterplace.dev/routing/aliases/)** over several deployments: round robin, least busy, lowest latency, lowest cost or adaptive, with cooldown.
- **[Translation](https://docs.enterplace.dev/routing/translation/)**: chat completions to Claude, Claude Code's messages requests to GPT, Gemini or a local model, and Codex's Responses requests to any provider.
- **[Cost on every answer](https://docs.enterplace.dev/routing/pricing/)** with built-in prices for most models, and an exact or semantic **[cache](https://docs.enterplace.dev/routing/caching/)** per rule.

### Operations

- **[Admin console](https://docs.enterplace.dev/operations/console/)** at `/console`: a Start here checklist for the first request, requests, analytics, people and keys, policy and spend, with OIDC or SAML sign-in and roles.
- **[Prometheus metrics](https://docs.enterplace.dev/operations/observability/)** and audit log shipping with Vector, Fluent Bit or the OpenTelemetry Collector.
- **[Container image and Kubernetes](https://docs.enterplace.dev/deploy/overview/)**: one non-root image built `FROM scratch` (`ghcr.io/eliransu/enterplace`), a Helm chart, Terraform for AWS, Google Cloud and Azure, Docker Compose and Cloudflare.
- **[HTTPS](https://docs.enterplace.dev/operations/deployment/)** with `--tls-cert` and `--tls-key`.
- **[Coming from LiteLLM](https://docs.enterplace.dev/migrate/from-litellm/)**: `enterplace import litellm` turns a LiteLLM proxy config into a Enterplace policy.

## Integrations

| Tool | Route | Guide |
|---|---|---|
| Codex CLI | `/v1/responses` | [docs](https://docs.enterplace.dev/integrations/codex/) |
| Claude Code | `/v1/messages` | [docs](https://docs.enterplace.dev/integrations/claude-code/) |
| Gemini CLI | `/v1beta/models/<model>:streamGenerateContent` | [docs](https://docs.enterplace.dev/integrations/gemini-cli/) |
| Cursor, Continue, Cline, Aider, OpenCode, Copilot, Zed and 8 more | `/v1/chat/completions` and others | [docs](https://docs.enterplace.dev/integrations/coding-tools/) |
| OpenAI and Anthropic SDKs | all | [docs](https://docs.enterplace.dev/integrations/sdks/) |

## Repository

```text
crates/
  enterplace-core      policy, routing, guardrails, audit chain, pricing (library, no HTTP)
  enterplace-server    the HTTP gateway (library)
  enterplace-console   the admin console assets
  enterplace-cli       the enterplace binary: start, serve, check, key, audit, kill, usage, budget, login, import, prices
  enterplace-bench     overhead benchmark and CI gate
enterprise/        enterprise features (commercial license, see enterprise/LICENSE)
deploy/            Helm chart, Terraform (AWS ECS, GCP Cloud Run, Azure Container Apps), Compose, Cloudflare, MDM
docs/              documentation site (Astro Starlight)
scripts/           CI, release and example checks
```

## Status

Enterplace is pre-1.0 (0.1.0, see [CHANGELOG.md](CHANGELOG.md)) and runs as one node on plain files, or as several replicas sharing a Postgres store. See [Project status](https://docs.enterplace.dev/getting-started/status/) for what is built, what is planned and what has been verified against which services.

## Contributing

New here? [CONTRIBUTING.md](CONTRIBUTING.md) gets you from clone to a running gateway in five minutes, and
[ARCHITECTURE.md](ARCHITECTURE.md) shows where each part lives. Issues labeled
[good first issue](https://github.com/eliransu/enterplace/issues?q=is%3Aopen+label%3A%22good+first+issue%22) name the files
to change and the test that proves it.

```bash
scripts/ci.sh
```

Runs the same checks as CI: format, clippy with warnings as errors, every test, the release build, every policy example through `enterplace check`, the overhead bench gate and the docs build. With `ENTERPLACE_TEST_DATABASE_URL`, Chrome and `psql` present it also drives the console's editing pages in a real Chrome (`scripts/console_edit_check.py`), which CI runs as its own `console-edit` job. Conventions are in [AGENTS.md](AGENTS.md).

## License

Enterplace is one repository with two licenses, as LiteLLM is:

- Everything outside `enterprise/` is under the [MIT License](LICENSE).
- `enterprise/` is under the [Enterplace Commercial License](enterprise/LICENSE): the source is there to read, and
  running it in production needs a valid Enterplace license key.

The root [LICENSE](LICENSE) states the split at the top, as LiteLLM's does.

The open source crates build, test and run without `enterprise/` and never import it. The `enterplace` binary in the
image is the enterprise build: with no license key it is the open source gateway, and a key unlocks the enterprise
features. See [License key](https://docs.enterplace.dev/operations/license/).
