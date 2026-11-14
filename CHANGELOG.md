# Changelog

Every change to Gantry that a user or operator can see, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
Gantry and Gantry Enterprise share one version number: the enterprise image of a version carries this repository at the
same version. How a release is made: RELEASING.md in the gantry-enterprise repository.

## [Unreleased]

### Guardrails

- `type: regex` and `type: keywords` guardrails: the policy's own RE2 patterns and word or phrase lists (case and
  whole-word options), each entry named so findings, refusals and masks say which one matched; block, mask or warn,
  on requests, answers or both.
- `shadow_until` on any guardrail: until that UTC date it records `action: shadow` and enforces nothing.
- `gantry guardrail test <name> --corpus <file>` and `POST /admin/guardrails/test`: a backtest of a guardrail over
  examples before it goes live, with hits, kinds, masked sample spans, and precision and recall on labelled examples.
- Nine more secrets kinds: `gcp_service_account_key`, `gcp_api_key`, `azure_connection_string`, `stripe_key`,
  `twilio_api_key`, `sendgrid_key`, `openai_project_key`, `anthropic_key` and `database_url`, measured on the new
  `gantry-detectors-v2` corpus. A URL's login part is no longer reported as an email address.
- `type: model_armor`: Google Cloud Model Armor through sanitizeUserPrompt and sanitizeModelResponse.

## [0.1.0] - Unreleased

The first tagged release: a governed AI gateway in one static binary. Every request carries a person's or workload's
identity, passes a policy decision and lands in a hash-chained audit log before Gantry forwards it with the provider key.

### Gateway and routes

- OpenAI routes: chat completions, Responses, embeddings, image generation, audio transcription and speech,
  moderations and rerank, plus `GET /v1/models` in the shape the caller expects.
- Anthropic routes for Claude Code and the Anthropic SDKs: messages and token counting.
- Passthrough to a provider's own API on the paths a rule names (`/passthrough/<provider>/<path>`), recorded, limited
  and charged like any other call.
- An MCP gateway at `/mcp`: tools from upstream MCP servers, limited per rule, each call audited.
- Proxy, CDN and caller address headers stay with Gantry and never reach a provider. `accept-encoding` is not
  forwarded, so every answer can be read for usage, guardrails and translation.

### Providers

- Provider kinds: OpenAI and compatible servers, Anthropic, Azure OpenAI, Claude on Amazon Bedrock (signed with AWS
  Signature Version 4), Gemini, and Gemini and Claude on Vertex AI.
- Translation both ways: chat completions to Claude models (`accept_chat`) and Claude Code's messages to chat models
  (`accept_messages`). A field that cannot be carried across is refused, never dropped.
- A catalog of 119 provider presets (`preset: groq`), each URL taken from the vendor's own API documentation, with
  `gantry providers` to list them.
- Provider keys from a file (`key_file`), rotated without a restart.
- A live test matrix (`scripts/live_matrix.py`, `.github/workflows/live.yml`): every route against each real provider
  kind, nightly, with a token cap per run. Without provider keys every cell says it was skipped.

### Identity and policy

- Gantry keys per person and workload, with an optional expiry, budget, model list and tokens-per-minute limit, issued
  from the command line, the admin API or the console.
- A policy file of rules by team, person or anyone, checked by `gantry check` with the line and the fix for every
  mistake. Policy and keys reload within 2 seconds, without a restart.
- Kill switches with a reason (`gantry kill`, `gantry unkill`).
- First run: `gantry init` writes a starter policy and `gantry serve` prints a one-time setup link that makes the first
  admin key, with a prompt to copy into a coding agent that connects a project to Gantry.
- `gantry login` gives a developer an expiring key of their own through single sign-on.

### Guardrails

- Built-in detectors for secrets and personal data, measured on a published corpus of 1,223 labelled lines with
  precision and recall per kind. Labelled medical record numbers and dates of birth are found.
- Seven guardrail vendors and outside services by webhook, on requests and on answers.
- A streamed answer can be checked as it comes and stopped partway (`check_stream_every`).

### Spend and routing

- Usage and cost of every answer, with prices built in for most models (`gantry prices`).
- Budgets per team, person or key, requests and tokens per minute, and a cache per rule.
- Retries, one fallback per provider, and model aliases over several deployments with weights, context window and
  content policy fallbacks, and a circuit breaker per deployment with half-open probes.

### Several gateways, one store

- With `store:` in the policy, every gateway on one Postgres database shares keys, kill switches and budgets. TLS to
  the database follows libpq's `sslmode` and `sslrootcert`, and a Unix socket (the Cloud SQL connector) works without
  TLS.

### Audit and observability

- A hash-chained audit log and `gantry audit verify`. The log cannot be removed or replaced while Gantry holds it, on
  Linux, macOS and Windows, and its lock holds across containers and machines on one share.
- Prometheus metrics on an address of their own (`--metrics`).
- OpenTelemetry traces over OTLP/HTTP, joined to the caller's trace, carrying no prompt, answer or key.

### Console and command line

- An admin console: audit log, people and keys, policy and spend, with sign-in by admin key or OpenID Connect.
- `gantry import litellm`: a policy from a LiteLLM proxy configuration.
- The command line is a library (`gantry_cli::run`), and the server has extension points (routes, console pages,
  `/healthz` fields, store migrations), so a binary that embeds Gantry adds its own commands and pages.

### Releases and deployment

- Reproducible builds: two builds from scratch give the same bytes, checked on every release.
- Signed releases: `SHA256SUMS` and SLSA provenance, signed with the release SSH key in `release/allowed_signers`, and
  a rollback check that an older binary still reads the newer one's data.
- A container image built `FROM scratch` that runs as a non-root user, and a Helm chart for one replica.
- The docs site: getting started, deploy guides for Docker, Kubernetes, AWS, Google Cloud and Azure, integrations,
  governance, providers, routing, operations, reference and migration guides from LiteLLM and Bifrost.

### Security

- YAML is read by serde-saphyr in place of serde_yaml_ng, which dropped the unmaintained unsafe-libyaml
  (RUSTSEC-2024-0449). Duplicate keys are refused and YAML 1.1 words such as `yes` stay text.
