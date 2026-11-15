<div align="center">

# Gantry

**The open source AI gateway built for governance.**

Every model request gets an identity, a policy decision and a tamper-evident audit record before it reaches a provider.

[![CI](https://github.com/eliransu/gantry/actions/workflows/ci.yml/badge.svg)](https://github.com/eliransu/gantry/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-gantry--docs.eliran.me-e3ff45.svg)](https://gantry-docs.eliran.me/)

[Documentation](https://gantry-docs.eliran.me/) · [Quickstart](https://gantry-docs.eliran.me/getting-started/quickstart/) · [Claude Code](https://gantry-docs.eliran.me/integrations/claude-code/) · [Policy reference](https://gantry-docs.eliran.me/governance/policy/)

</div>

---

Gantry sits between your people, agents and workloads and the model providers they call. Claude Code, Codex, Cursor and any OpenAI or Anthropic SDK point at Gantry instead of the provider. For every request, Gantry:

1. **Identifies** the caller by a personal Gantry key, never a shared provider key.
2. **Decides** by a policy file: which person or team may use which model, within what budget, under which guardrails.
3. **Records** the decision in a hash-chained audit log, before anything is forwarded.
4. **Forwards** the request with the provider's key in place of the caller's.

A request that cannot be recorded is refused. Gantry is one static binary with no database: policy, keys and audit log are plain files.

Everything outside `enterprise/` is Apache 2.0. The enterprise features in `enterprise/` are under a commercial license and need a license key; see [License](#license).

## Quickstart

Install the `gantry` CLI (macOS and Linux, x86_64 and arm64; the release signature and SHA256 are checked) and start it:

```bash
curl -fsSL https://gantry.eliran.me/install.sh | sh
export OPENAI_API_KEY=sk-...
gantry start
```

Or `brew install eliransu/tap/gantry`. Or run the image:

```bash
docker run --name gantry -p 8080:8080 -v gantry-data:/var/lib/gantry -e OPENAI_API_KEY=sk-... ghcr.io/eliransu/gantry
```

The image is public. The first start writes an observe-mode policy (nothing is blocked, every request is recorded) and
an admin key to the `gantry-data` volume, prints the key once as `export GANTRY_KEY=gantry_...`, and serves on
`http://localhost:8080`. `ANTHROPIC_API_KEY` and `GEMINI_API_KEY` work too.

Send a request through it:

```bash
export GANTRY_KEY=gantry_...
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GANTRY_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello."}]}'
```

Every request is now in `/var/lib/gantry/gantry-audit.jsonl` on the volume. Prove nothing was changed:

```bash
docker exec gantry /gantry audit verify /var/lib/gantry/gantry-audit.jsonl
```

With Postgres, for a team: the [Docker Compose](https://gantry-docs.eliran.me/deploy/docker/) guide. From source:

```bash
git clone https://github.com/eliransu/gantry.git && cd gantry
cargo build --release
OPENAI_API_KEY=sk-... target/release/gantry start
```

Full walkthrough: [Quickstart](https://gantry-docs.eliran.me/getting-started/quickstart/).

## Features

### Governance

- **[Keys per person and workload](https://gantry-docs.eliran.me/governance/keys/)**: hashed at rest, with optional expiry, budget, model list and token limit per key.
- **[Self-service keys through SSO](https://gantry-docs.eliran.me/governance/single-sign-on/)**: `gantry login` issues a developer an expiring key through your identity provider.
- **[Policy as code](https://gantry-docs.eliran.me/governance/policy/)**: first-match rules by team, person or anyone. `gantry check` rejects unknown fields with file, line and fix. Reloads in 2 seconds without a restart.
- **[Budgets and rate limits](https://gantry-docs.eliran.me/governance/budgets-and-rate-limits/)**: dollars per team, person or key, reserved at admission. Requests and tokens per minute.
- **[Guardrails](https://gantry-docs.eliran.me/governance/guardrails/)**: built-in secret and personal data detectors, seven guardrail vendors, and your own services by webhook. Block, mask or record.
- **[Kill switches](https://gantry-docs.eliran.me/governance/kill-switches/)**: stop a person, team, key or model at once.
- **[Tamper-evident audit log](https://gantry-docs.eliran.me/governance/audit-log/)**: one hash-chained record per request, refusals included, verified with `gantry audit verify`.

### Routing

- **[Providers](https://gantry-docs.eliran.me/providers/overview/)**: OpenAI, Anthropic, Azure OpenAI, Claude on Amazon Bedrock and Vertex AI, Gemini, and any OpenAI-compatible server (Groq, Mistral, Together, Fireworks, DeepSeek, OpenRouter, Ollama, vLLM, LM Studio).
- **[Retries and fallbacks](https://gantry-docs.eliran.me/routing/retries-and-fallbacks/)** per provider, and **[model aliases](https://gantry-docs.eliran.me/routing/aliases/)** over several deployments with weights and cooldown.
- **[Translation](https://gantry-docs.eliran.me/routing/translation/)**: chat completions to Claude, or Claude Code's messages requests to GPT, Gemini or a local model.
- **[Cost on every answer](https://gantry-docs.eliran.me/routing/pricing/)** with built-in prices for most models, and an exact-match **[cache](https://gantry-docs.eliran.me/routing/caching/)** per rule.

### Operations

- **[Admin console](https://gantry-docs.eliran.me/operations/console/)** at `/console`: audit log, people and keys, policy and spend, with OIDC sign-in and admin and read-only roles.
- **[Prometheus metrics](https://gantry-docs.eliran.me/operations/observability/)** and audit log shipping with Vector, Fluent Bit or the OpenTelemetry Collector.
- **[Container image and Kubernetes](https://gantry-docs.eliran.me/deploy/overview/)**: one non-root image built `FROM scratch` (`ghcr.io/eliransu/gantry`), a Helm chart, Terraform for AWS, Google Cloud and Azure, Docker Compose and Cloudflare.
- **[HTTPS](https://gantry-docs.eliran.me/operations/deployment/)** with `--tls-cert` and `--tls-key`.
- **[Migrate from LiteLLM](https://gantry-docs.eliran.me/migrate/from-litellm/)**: `gantry import litellm` turns a LiteLLM proxy config into a Gantry policy.

## Integrations

| Tool | Route | Guide |
|---|---|---|
| Claude Code | `/v1/messages` | [docs](https://gantry-docs.eliran.me/integrations/claude-code/) |
| Codex CLI | `/v1/responses` | [docs](https://gantry-docs.eliran.me/integrations/codex/) |
| Cursor, Continue, Cline, Aider, OpenCode | `/v1/chat/completions` | [docs](https://gantry-docs.eliran.me/integrations/cursor/) |
| OpenAI and Anthropic SDKs | all | [docs](https://gantry-docs.eliran.me/integrations/sdks/) |

## Repository

```text
crates/
  gantry-core      policy, routing, guardrails, audit chain, pricing (library, no HTTP)
  gantry-server    the HTTP gateway (library)
  gantry-console   the admin console assets
  gantry-cli       the gantry binary: serve, check, key, audit, kill, login, import, prices
  gantry-bench     overhead benchmark and CI gate
enterprise/        enterprise features (commercial license, see enterprise/LICENSE)
deploy/            Helm chart, Terraform (AWS ECS, GCP Cloud Run, Azure Container Apps), Compose, Cloudflare, MDM
docs/              documentation site (Astro Starlight)
scripts/           CI, release and example checks
```

## Status

Gantry is pre-1.0 (0.1.0, see [CHANGELOG.md](CHANGELOG.md)) and runs as a single node. See [Project status](https://gantry-docs.eliran.me/getting-started/status/) for what is built, what is planned and what has been verified against which services.

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
features. See [License key](https://gantry-docs.eliran.me/operations/license/).
