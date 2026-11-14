# Changelog

Every change to Gantry that a user or operator can see, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
The open source crates and the enterprise features in `enterprise/` (commercial license) share one version number and
one repository. How a release is made: RELEASING.md.

## [Unreleased]

### Cloud providers and translation

- `kind: bedrock_converse`: every model family Bedrock serves through Converse and ConverseStream (Anthropic, Meta
  Llama, Mistral, Cohere, Amazon Nova, AI21, DeepSeek, Qwen, OpenAI gpt-oss) on the chat completions and Responses
  routes, translated both ways with tool use, images and documents, and Claude Code through `accept_messages`.
  Amazon Titan and Cohere embeddings on Bedrock. Bedrock token counts (CountTokens) for `kind: bedrock`.
- Azure OpenAI signs in with Microsoft Entra ID when it has no key: client credentials, AKS workload identity and
  managed identity, renewed in process. The Responses API and embeddings reach Azure deployments.
- Vertex AI: embeddings (`:predict`), rerank (the Ranking API), Claude token counts (count-tokens), Veo videos, and
  `kind: vertex_openai` for Model Garden models behind the OpenAI-compatible endpoint.
- Embeddings on every provider that offers them: OpenAI, Azure, Bedrock, Vertex AI, Gemini, Cohere, watsonx.ai.
- `POST /v1/responses` reaches Anthropic, Bedrock, Vertex AI, Gemini, Cohere and watsonx.ai, translated through chat,
  with Responses streaming events and function calls; state the provider does not keep is refused by name.
  `chat_as_responses: true` sends chat requests to Responses-only models.
- Reasoning maps across providers: `reasoning_effort` becomes Claude's thinking budget (1024, 4096, 16384), Gemini's
  thinking budget or level, Nova's and gpt-oss's settings on Converse, and Cohere's thinking; Claude Code's thinking
  budget becomes `reasoning_effort`; readable reasoning comes back as `reasoning_content`. The table is on the
  providers overview. **Changed:** `reasoning_effort` `low`, `medium` and `high` to Claude now sends a thinking budget
  instead of `output_config.effort`; `xhigh` and `max` still send effort.
- Signed passthrough: `/bedrock/<path>` and `/vertex/<path>` (and `/passthrough/<provider>/` for those kinds, which
  `gantry check` no longer refuses) are signed with SigV4 or the Google token, with the model in the path decided.
- `/v1/videos` (Sora, and Veo through the same route) and `/v1/containers`, owned by their creator, guarded,
  budgeted and priced with the new `per_second` and `per_call` price fields (containers: see below).
- Native kinds `cohere` (v2 chat, embed, rerank) and `watsonx` (IBM watsonx.ai, IAM token traded for the API key).
  Presets `cohere-native`, `watsonx`, `deepseek`, `databricks` and `snowflake` (the last two need your own URL).
- A model priced under no name of its own is priced as the Bedrock model ID or Azure deployment it is called by.
- **Changed (migration):** code interpreter containers are allowed by a rule field, `containers: { sizes: [1g, 4g] }`,
  instead of the model names `container-1g`, `container-4g`, `container-16g` and `container-64g`, which are no longer
  models or prices. A rule without `containers:` allows none: move each `container-<size>` listed under a rule's
  `models:` into its `containers: { sizes: [...] }`. A container is now priced from OpenAI's per-session price by size
  (0.03, 0.12, 0.48, 1.92 US dollars per 20 minutes, by the minute, 5 at least): one session reserved at creation,
  charged for the minutes it lived when it expires or is deleted. Usage records say `model: container`,
  `container_size` and `price: per_minute`.
- Video prices checked against the providers' pages on 2026-11-14 and cited in the price table and docs:
  `veo-3.0-fast-generate-001` is 0.10 per second (it was 0.15, a wrong figure); `veo-3.1-generate-001`,
  `veo-3.1-fast-generate-001` and `veo-3.1-lite-generate-001` added. Google lists Veo "per count"; the per-second unit
  is LiteLLM's (MIT price map), and the docs say so. Sora 2 is shut down at OpenAI since 2026-09-24; its prices stay.
- `GET`, `DELETE` and `cancel` on `/v1/responses/<id>`, and `GET /v1/responses/<id>/input_items`, for the response's
  creator alone (others get 404), at OpenAI or Azure. A response translated for another provider is kept by Gantry,
  for an hour in memory, when the request says `"store": true`.
- Async jobs: `POST /v1/async/<route>` runs a model request in the background on the governed route and
  `GET /v1/async/<route>/<id>` reads its answer, held for its submitter for an hour (`x-gantry-async-ttl`).
- Azure: images, transcription, speech and legacy completions on deployment paths, and the v1 API (a `url` ending in
  `/openai/v1`, no `api_version`), with images and audio sent to its preview.
- Vertex AI and the Gemini API count a Gemini model's tokens (`countTokens`) for `POST /v1/messages/count_tokens`.
- Native kinds `sagemaker` (SageMaker endpoints with an OpenAI-shaped container, signed with SigV4, streams included)
  and `replicate` (predictions translated from chat, waited for and cancelled after 60 seconds). Presets `sagemaker`,
  `replicate`, `oci` (OCI Generative AI, API key) and `triton` (Triton's OpenAI-compatible frontend).
- A Bedrock stream through signed passthrough is charged the usage its events report, not its reservation.
- Files written into a container are read by the request guardrails, and files read back from one by the answer
  guardrails, when they are text. Video requests take an `input_reference` image, as multipart or JSON, with the
  prompt guarded; Veo gets the image in its instance.

### Browser access

- `cors:` in the policy: `allowed_origins` lists the browser origins (or `"*"`) that may call Gantry's routes. Off by
  default. Gantry answers the preflight itself and never allows credentials; the console and the admin API answer no
  other origin. The Claude for Office and Open WebUI guides use it in place of a reverse proxy.

### One repository, one image

- The enterprise features moved into this repository as `enterprise/`, under their own commercial license
  (`enterprise/LICENSE`); everything outside it stays Apache 2.0. The open source crates still build, test and install
  (`cargo install --path crates/gantry-cli`) on their own and never import `enterprise/`.
- One image: **`ghcr.io/ggantry/gantry-enterprise` is renamed `ghcr.io/ggantry/gantry`**. Change the image in your
  Compose file, Helm values (`image.repository`), Terraform `image` variable and Cloudflare `wrangler.jsonc`. Its
  binary is `/gantry` (was `/gantry-enterprise`): update `kubectl exec ... -- /gantry-enterprise` commands. Without a
  license key it runs as the open source edition; a valid key unlocks the enterprise features, as before.
- The Helm chart, Terraform modules, Cloudflare template and MDM files are at `deploy/` in this repository, and still
  ship inside the image under `/deploy`. The old single-replica chart and the plain manifests in
  `deploy/kubernetes/` are gone: the StatefulSet chart replaces both.
- Release tarballs carry the same binary as the image, with `LICENSE` and `LICENSE-enterprise`.

### Fixed

- Cloudflare (and any `GANTRY_AUDIT_SEGMENTS_URL` deployment) with a store: a sealed audit segment is removed from the
  disk only after the console's request log has copied its records, as it already waited for the audit export and
  alerting. Before, a segment could be retired between two copies and its requests never appeared in the request log.
- The guardrail backtest admin API (`POST /admin/guardrails/test`) needs `edit_policy`, not `credentials`.
- A Gemini Live session's decision record, written when its setup names the model, carries the caller's `user_agent`.
- Analytics budget forecasts measure each budget over its own period and time zone (`per: week`, `6h`, `tz:`), not
  over the UTC month, and with a store sum the period's spend in Postgres instead of folding up to 200,000 rows.

### Guardrails

- `type: regex` and `type: keywords` guardrails: the policy's own RE2 patterns and word or phrase lists (case and
  whole-word options), each entry named so findings, refusals and masks say which one matched; block, mask or warn,
  on requests, answers or both.
- `shadow_until` on any guardrail: until that UTC date it records `action: shadow` and enforces nothing.
- `gantry guardrail test <name> --corpus <file>` and `POST /admin/guardrails/test`: a backtest of a guardrail over
  examples before it goes live, with hits, kinds, masked sample spans, and precision and recall on labelled examples.
  The admin API call needs the `edit_policy` permission (it asked for `credentials` at first).
- Nine more secrets kinds: `gcp_service_account_key`, `gcp_api_key`, `azure_connection_string`, `stripe_key`,
  `twilio_api_key`, `sendgrid_key`, `openai_project_key`, `anthropic_key` and `database_url`, measured on the new
  `gantry-detectors-v2` corpus. A URL's login part is no longer reported as an email address.
- `type: model_armor`: Google Cloud Model Armor through sanitizeUserPrompt and sanitizeModelResponse.

### Access and budget hierarchy

- Organizations: `orgs:` in the policy, `org:` on keys, rules, limits and roles. Each organization has its own rules,
  budgets, keys and console view; counters and records are kept per organization.
- End customers (`customer:` on a key, or `x-gantry-customer` for names a rule's `customers:` lists) and request tags
  (`tags:` on a key, or `x-gantry-tags` for tags a rule lists). An unlisted name is refused by name. Records carry
  `org`, `customer` and `tags`; `principals: { tag: ... }` names keys by tag.
- Budgets at every scope through `limits:` (global, organization, team, person, key, customer, tag, model), several
  per place, per model on a rule, with periods from a minute to a year (`day`, `week`, `6h`, `3mo`, ...) aligned to
  an IANA time zone (`tz:`). Fixed-length windows such as `per: 30d` start again every 30 days.
- `parallel:` on a rule, a key or a scope caps requests in flight, shared across replicas with a store
  (`parallel_limited`).
- Within a kind of scope each limit comes from the most specific entry; `gantry explain` and `GET /admin/explain` list
  every limit that applies with where it is written, what it overrides and (from the gateway) what it has spent.
- Access profiles (`profiles:`) a rule includes: models, guardrails, tools and limits, with the rule's own values
  winning and every override listed.
- Console roles (`roles:`) with fine-grained permissions (`see_keys`, `issue_keys`, `revoke_keys`, `kill`,
  `credentials`, `edit_policy`, `see_spend`, `see_records`, `see_bodies`), given to keys with `role:` or through
  single sign-on with `sso_values`, enforced in the console and the admin API.
- The store's schema gains a fourth migration: the new key fields.

### Added

- `GET /readyz`: ready only when a request would be served (audit log writable, store reachable when set, a policy
  with keys or a JWT issuer, not draining, and any check an embedder adds). `/healthz` stays liveness. On `SIGTERM`
  Gantry stops accepting, answers `/readyz` with 503 and finishes requests in flight.
- Key management: `PATCH /admin/keys/<prefix>` and `gantry key update` change a key's expiry, budget, models, tpm,
  rpm, parallel, customer, tags, metadata, routes and source ranges, each change recorded with its before and after;
  `GET /admin/keys/<prefix>` and `gantry key info` show a key with its spend; `POST /admin/keys/<prefix>/rotate` and
  `gantry key rotate --grace 48h` make a new key and keep the old one for the grace, recording every use of it.
- Access: `from:` address ranges on keys and rules with `trusted_proxies:` for `X-Forwarded-For` (`ip_not_allowed`),
  key `routes` (`route_not_allowed`), key `rpm`, and `jwt:` issuers whose RS256 or
  ES256 tokens are accepted in place of a Gantry key and recorded with their issuer and subject.
- Routing: `balance: lowest_latency` (90th percentile time to first byte) and `lowest_cost`, deployments kept `for:` a
  team or tag with `x-gantry-tags` limited to the rule's `tags:`, `region:` labels with `regions:` residency on rules
  (a refusal, never a preference), and `session_affinity` for coding agent sessions. Each choice and its reason is in
  the decision record's `routing`.

### Added

- The policy kept in the store as versions (`store.policy_from: store`): the console and `PUT /admin/policy` save a
  new version, checked as `gantry check` checks a file, live on every gateway within 2 seconds. Optional approval by a
  second admin (`store.approval: true`), a dry run against recent requests, one-click rollback, export and import as
  YAML, and every change in the audit chain. The file stays the source by default, for GitOps.
- Console pages: Models (add a model with its price and aliases, change a price), Teams, key editing on People and
  workloads, and Policy versions with the editor, diffs, approval, dry run and rollback.

### Changed

- Adding, removing or repointing a provider no longer needs a restart: the reload builds its route.
- The console's People page reads keys from the store when there is one.

### Added

- Files, batches and fine-tuning jobs served natively (`/v1/files`, `/v1/batches`, `/v1/messages/batches`,
  `/v1/fine_tuning/jobs`): each owned by the person who created it, every batch line decided by the policy and the
  guardrails before the provider sees the file (a refused line is named by number), the batch's estimate reserved at
  batch prices against budgets, and results metered with one usage record per line.
- `file_retention_days` on a rule: uploads expire at the provider and Gantry deletes what is left when the time is up.
- Realtime sessions over WebSocket: OpenAI Realtime and Gemini Live, decided at connect (Gemini on its setup),
  metered per response from the provider's usage events, ended by a kill switch or a spent budget, and recorded
  without content.
- `POST /v1/completions` (legacy text completions) for openai providers, guarded on its prompt and priced from usage.

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

The commercial features (`enterprise/`, licensed by key), in the same image:

### Enterprise: One image

- `ghcr.io/ggantry/gantry` (first published as `ghcr.io/ggantry/gantry-enterprise`) for amd64 and arm64, under 50 MB, running as a non-root user. It serves
  `/etc/gantry/gantry.policy.yaml` by default and runs every open source command too (`key new`, `audit verify`,
  `check`), so no separate binary is needed.
- The image carries the Helm chart and the Terraform modules under `/deploy`.

### Enterprise: License

- A signed license key (`GANTRY_LICENSE` or `GANTRY_LICENSE_FILE`), checked offline, unlocks the enterprise features.
  An expired license keeps them on for 30 days, then turns them off; model traffic is never stopped. `/healthz` shows
  the license without its token.

### Enterprise: Members and access

- Members with owner, admin and viewer roles, invites by one-time link and password sign-in, on the gateway's own
  console. Removing a person revokes every key named with their email and ends their session at once.
- In the Gantry app: single sign-on per organization through its own OpenID Connect provider (Okta, Entra ID, Google
  Workspace), two-step sign-in with recovery codes, and SCIM 2.0 provisioning.
- Scoped, expiring admin API tokens for staff, each write recorded with the caller's name.

### Enterprise: Governance

- Policy versions with diffs, a dry run against recorded traffic, and approval by a second admin before a change goes
  live.
- Audit export to a signed webhook, Splunk HEC or Datadog, a backfill of up to 90 days, a pull API for a SIEM that
  cannot receive a POST, retention, legal hold and an NDJSON archive.
- Compliance evidence reports for SOC 2, ISO 27001, the EU AI Act and the NIST AI RMF.
- Workload identity: OIDC token exchange for short-lived keys.
- Provider keys from files, HashiCorp Vault or AWS Secrets Manager, rotated without a restart.

### Enterprise: Hosted service and hybrid nodes

- A control plane and web app: sign up, keys, gateways, audit log, spend by team, person and model, and a back office
  for staff.
- A hosted gateway per organization, and hybrid nodes that pull their configuration, ship an allowlist of audit fields
  and guardrail findings, and keep serving when the control plane is down.
- Watch mode for Claude Team and Enterprise subscriptions: Claude Code's own telemetry, usage by person and model,
  with no prompt, answer or tool content stored.
- A device agent with enrolment tokens, a profile per organization, coverage and drift reporting, and MDM templates.
- A page that gives a coding agent the prompt to connect a project to the gateway.

### Enterprise: Deployment

- Docker Compose with Postgres, written from the Docker guide and tested end to end on every change.
- A Helm chart run as a StatefulSet, each replica with its own audit log, several replicas sharing a Postgres store,
  tested on kind.
- Terraform modules for AWS (ECS, RDS, EFS), Google Cloud (Cloud Run, Cloud SQL, Filestore) and Azure (Container Apps,
  Azure Database for PostgreSQL, Azure Files).

### Enterprise: Security

- Fixes from the cloud security review: a credential per hosted gateway, SCIM and password links limited to people of
  one organization, outbound fetches over HTTPS only with no redirects or private addresses, read-only staff, and rate
  limits on public forms.
