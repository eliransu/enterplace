# Changelog

Every change to Gantry that a user or operator can see, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
The open source crates and the enterprise features in `enterprise/` (commercial license) share one version number and
one repository. How a release is made: RELEASING.md.

## [Unreleased]

### Guardrails: five more vendors

- New guardrail types, each asked in the vendor's own API: `prisma_airs` (Palo Alto Networks Prisma AIRS AI
  Runtime, with `profile_name`), `enkrypt` (Enkrypt AI), `grayswan` (Gray Swan Cygnal, with `policy_id`),
  `cisco_ai_defense` (Cisco AI Defense, `region` us, eu or ap) and `mistral_moderation`. Findings are recorded by
  kind, never content. Prompt Security, Pillar Security, Noma, Qualifire and Zscaler AI Guard are not built in: none
  publishes its request and answer fields without an account.

### Providers: images, rerank and counts across clouds, OCR, Azure and AWS SDK keys

- `POST /v1/images/generations` reaches Imagen and Gemini image models on the Gemini API and Vertex AI, and Amazon
  Titan Image Generator, Nova Canvas and Stability AI on Bedrock (`bedrock_converse`), translated both ways. A field
  with no equivalent is refused by name. Images priced `per_image` are charged for each image returned.
- `POST /v1/rerank` reaches Cohere Rerank 3.5 and Amazon Rerank on Bedrock.
- `POST /v1/messages/count_tokens` counts Converse models through Bedrock's CountTokens. For a provider with no count
  API, Gantry answers with its own estimate, marked `"estimated": true` and `x-gantry-token-count: estimate`.
- New route `POST /v1/responses/input_tokens`: as sent to OpenAI and Azure, as a messages count elsewhere.
- New route `POST /v1/ocr` (Mistral's OCR API), priced by the page with the new `per_page` price field.
- The Gantry key is read from `api-key`, the header Azure OpenAI's SDKs send, with the same ambiguity check.
- boto3 and the AWS SDKs reach Bedrock through Gantry on `/model/<id>/converse`, `/converse-stream`, `/invoke`,
  `/invoke-with-response-stream` and `/count-tokens` with a Gantry key (`AWS_BEARER_TOKEN_BEDROCK`, or `x-api-key`
  beside a SigV4 signature, which is removed). The caller's rule decides the model; refusals come back in the AWS
  error shape (`x-amzn-errortype`).

### MCP gateway: servers without a restart, more transports, prices, token exchange, sessions

- MCP servers are added, changed and removed without a restart: by a saved policy file, `SIGHUP`, or
  `PUT`/`DELETE /admin/mcp/<name>` with the policy in the store. A server reached as before keeps the sessions
  Gantry holds at it. `/mcp` is served whenever Gantry runs with a policy, so the first server can be added the same
  way. A reload that names an unset variable is rejected and the version in use stays.
- `transport: sse` reaches servers that speak the older HTTP+SSE transport (MCP 2024-11-05). `transport: stdio`
  starts a server as a process (`command`, `args`, `env`): only a command listed in `GANTRY_MCP_STDIO_ALLOW` in the
  gateway's own environment, with an environment emptied of everything but what `env:` names. The policy alone
  cannot make the gateway run a program.
- `call_price_usd` and `tool_prices` on a server price its tool calls. A priced call the server answered writes a
  usage record (`provider: "mcp"`, the tool as its model) and counts against the caller's budgets; with a budget
  spent, the call is refused with `budget_exceeded` before it reaches the server.
- `user_auth: token_exchange` trades the token a caller sends in `x-gantry-subject-token` for the server's at the
  identity provider's token endpoint (RFC 8693); `user_auth: on_behalf_of` sends the on-behalf-of form. Records say
  `upstream_auth` and hold neither token.
- `GET /admin/mcp/sessions` and the console's MCP sessions page list the MCP clients connected to a gateway and each
  person's own account at a server; `DELETE /admin/mcp/sessions/<id>` ends one. New refusal code: `session_revoked`.
- A rule's `mcp_clients` names the MCP client applications that may connect, by the name a client gives itself, its
  user agent, or `oauth:<client id>`. New refusal code: `mcp_client_not_allowed`.
- An MCP server can no longer be named `sessions`.

### Plugin events: guardrail contract v2

- A new guardrail type, `events`, sends an outside service the whole conversation as typed events: `system_prompt`,
  `user_message`, `assistant_message`, `reasoning`, `tool_definitions`, `tool_call`, `tool_result`, `mcp_tool_call`,
  `mcp_tool_result` and realtime text, the same on chat completions, the Responses API, Anthropic messages, Gemini
  and Bedrock Converse bodies. Each event carries a `session_id`, a `turn_id`, an `event_index` and a deterministic
  `event_id`, computed from the request alone, so every replica agrees. Only the new events of a call are sent;
  `history: true` adds the earlier ones. Contract v1 (`type: webhook`) is unchanged.
- `mode: enforce` waits for the verdict on requests, answers, streamed windows, MCP tool calls and results, and
  realtime text: `allow`, `block`, `mask` (per event: text, or a tool call's arguments) and `session_action: end`,
  which refuses the session with `session_ended` for `session_end_seconds`, on every replica with a store.
  `mode: observe` queues envelopes and sends them in the background, batched (`batch_url`) and retried, and never
  delays a request; a full queue drops and counts in `gantry_events_dropped_total`.
- `stream: { chunk_chars, hold }` sends a streamed answer's text in windows; with `hold: true` the caller's tokens
  wait for each window's verdict, and a block ends the stream with the caller's API's error event.
- Deliveries are signed the Standard Webhooks way with `secret_env`. `on_failure`, `timeout_ms`, `headers_env` and
  `shadow_until` work as on other guardrails.
- `applications:` in the policy and on a rule (or `x-gantry-application` and `x-gantry-application-intent`, where
  the rule allows) give each envelope the application's name and stated purpose. New refusal code:
  `application_not_allowed`.
- Decision and usage records carry `session` and `turn`, and an `events` entry per plugin with findings by kind,
  event kind, index and severity, never content. `GET /admin/usage` and the request log filter by `session` and
  group by `turn`.
- A binary that embeds Gantry sets `Extension::events` to judge the same envelopes in process.
- `examples/plugins/event-printer`: a reference plugin in one Python file that prints the event stream and blocks
  a tool call by name. Docs: governance/plugin-events.

### Plugin events: every stream, every route, masks in held streams

- Streamed answers are shown to events plugins in windows on Anthropic messages, the Responses API and Gemini's
  `streamGenerateContent` as on chat completions, and a block ends the stream with each API's own error event.
- With `stream.hold: true`, a `mask` verdict on a window rewrites the window and the stream goes on, where it used
  to end the stream. A streamed tool call waits for the verdict on the whole answer: a blocked one never reaches the
  caller, and a masked one reaches the caller with the plugin's arguments. Events that can still be masked carry
  `held: true`. Without hold a mask of a window is a verdict that does not fit, and `on_failure` applies.
- A masked Gemini tool result that is not a JSON object is sent as `{"output": "<the text>"}`, where the request
  used to be refused with a 502.
- Several events guardrails on one rule run in the order of the rule's `guardrails` list, and each sees the events
  as the ones before it masked them.
- A Responses API request with `previous_response_id` takes its session and turn from the response Gantry recorded
  as the caller's, so a chain stays one session with no header.
- Embeddings, completions, speech, moderations, image prompts, token counting, known-shape passthrough bodies, each
  line of a batch (`phase: batch`), each line of its results (`phase: batch_result`) and a video job's prompt are
  events, and verdicts on them are obeyed.
- The sessions a plugin ended are read from the store with its 500 ms poll, not on each request: an enforcing
  plugin with a store costs no store round trip per request. Other replicas refuse an ended session within a second.
- An observing plugin's answer record is no longer waited for before the answer is returned.
- A binary's own plugin (`Extension::events`) sees realtime text on a rule with no guardrail.
- The console's Requests page filters by session, and a row's detail shows its session and turn.
- `gantry-bench --events` measures the gateway with an events guardrail in observe mode on every rule.

### Watch mode in the self-hosted gateway (Gantry Enterprise)

- License feature `watch`: the gateway receives Claude Code's own OpenTelemetry export at `POST /otlp/v1/metrics` and
  `POST /otlp/v1/logs` (OTLP over HTTP, protobuf or JSON), for people on Claude Team and Enterprise seats whose
  requests cannot go through a gateway. It records who used Claude Code, models, tokens by type, estimated cost,
  lines, commits, pull requests and tool decisions. It never blocks or budgets, and never keeps prompt, answer or tool
  text, even when Claude Code is told to send it.
- Watch tokens (`gantry_watch_...`) per team or person, kept as a hash, expiring and revocable, at
  `/console/watch/tokens`. `gantry watch setup --gateway <url> --team <team>` creates one and prints Claude Code's
  managed settings for Claude Team, Claude Enterprise, device management and a single developer.
- New audit record type `watch`, one per reported model request, error, tool decision, tool result and prompt. The
  request log has a new dimension, `source`: watched requests are rows with `source` `watch` on the Requests and
  Analytics pages and in `/admin/usage` (`?source=watch`, `group_by=source`), and count against no budget.
  `gantry audit coverage` lists them as the tool `claude-code (watch)`. Alert rules on spend by amount and on
  unusual spend count watched cost. Audit export and retention cover the records as any other.
- `GET /console/watch/summary.json`: sums per person, model and tool. Tables in namespace `enterprise.watch`
  (`enterprise_watch_tokens`, `enterprise_watch_seen`, `enterprise_watch_series`, `enterprise_watch_daily`), which
  follow the retention period and legal hold.
- The receiver takes gzip exports (`Content-Encoding: gzip`, Claude Code's `OTEL_EXPORTER_OTLP_COMPRESSION=gzip`).
  The 4 MB limit is counted on the unpacked export, and unpacking stops there. Another compression is refused with
  `unsupported_encoding`. OTLP over gRPC and traces are not supported.
- On a team token, the email Claude Code reports becomes the name that person's gateway traffic has: the holder of
  a key whose `metadata` has that `email`, or of a key named by it. An email of the policy's `teams:` or of Members
  (SCIM's people among them) stays the email. Anyone else is listed in `summary.json` under `not_known_members`.
  A record whose `person` is a key holder's name keeps the reported address in `email`.
- Watch tokens can belong to an organization (`"org"`, `gantry watch setup --org`): their records carry `org`, and
  with `audit: { per_org: true }` go to that organization's chain. Tables: `enterprise_watch_tokens.org`.
- The daily digest's spend and top users include watched cost, and a `Watched:` line says how much of it was.
- The hosted app's watch page is not carried over: a console page waits for a design.

### Security

- Watch tokens and device enrolment tokens follow the admin's role (Gantry Enterprise). An admin whose role is kept
  to teams (`teams:`) could create, list and revoke watch tokens and enrolment tokens of any team, and an admin key
  sent as a bearer token to `/console/watch/tokens` or `/console/devices/tokens` acted with no role at all, so its
  organization or teams were not applied. Now a role kept to an organization, teams or customers reaches only its
  own tokens, by key and by console session: a token outside it is not listed, revoking it answers `404`, and
  creating one answers `403` with `outside_role` (`other_org` for another organization). A role kept to teams
  cannot create a token without a team.
- Enrolment tokens belong to the organization of the admin who created them (`org` in the list), or to the one an
  admin of the whole install names with `"org"` in the body, which must be one the policy lists under `orgs:`.
  Tables: `enterprise_device_tokens.org` (namespace `enterprise.devices`, migration 4).
- What an admin kept to part of the install reads follows the role too (Gantry Enterprise). An admin whose role is
  kept to an organization or to teams read every person in `GET /console/watch/summary.json`, every device in
  `GET /console/devices/devices.json` and on the Devices page, and every MCP server in `GET /console/devices/mcp`,
  and could approve or block any server and remove any device. Now the summary holds the sums of tokens within the
  role, the device list holds the role's teams' devices enrolled with a token of the role's organization (each
  device now carries `org`), and the MCP list holds those devices' servers. Deciding on a server none of them has
  answers `403` with `outside_role`, and removing a device outside the role answers `404`. Sums watched before
  this belong to no organization. Tables: `enterprise_watch_daily.org` (namespace `enterprise.watch`, migration 3).

### Releasing

- `scripts/version.py` (run by CI, `scripts/release.sh bump` and the release workflows) fails when a store
  migration list changed since the previous release tag and the version is not a minor version above that tag,
  naming the namespace and the version to bump to. The lists' fingerprints are kept in `release/migrations.txt` and
  `enterprise/migrations.txt`, which a test of each crate checks against the code.
- `PgStore::close` stops a store's thread and closes its connections, for a program that embeds the gateway and is
  done with its store before it exits. The enterprise tests call it: a finished test used to leave its connections
  open, and a run on 16 cores peaked near 100 of them. It now peaks under 50.
- Each store test drops its database when it ends (`gantry_server::store::TestDatabase`, in the open source and
  the enterprise tests), and `scripts/console_edit_check.py --fresh` drops the one it made. A run of
  `scripts/ci.sh` used to leave about 1 GB of test databases in the Postgres it ran against.

### Fixed: a parallel place comes back with the answer

- A request's place under a `parallel` limit (key or `limits:`) is given back as soon as its answer has ended, not
  when its usage record is written, so a caller's next request right after an answer is no longer refused with
  `parallel_limited`.

### Fixed: deleting a running background response

- A background response deleted before Gantry saw it end is read at the provider before the delete is sent, so it is
  charged the usage the provider last reported for it (it was read after the delete, which the provider no longer
  answers, and always charged its reservation). With no usage reported it is still charged its reservation.

### Provider proxies everywhere

- A provider's `proxy_env` now carries its realtime sessions (OpenAI Realtime, Gemini Live; `headers_env` too) and
  its cloud sign-in: AWS STS, Google's token endpoint, Microsoft Entra ID and IBM Cloud IAM. The metadata services
  are always reached directly.

### Deployment limits: actual tokens, every replica

- A deployment's `tpm` counts each request at its estimate while it runs and at the tokens its answer used once it
  is settled.
- With a store, `max_parallel`, `rpm` and `tpm` count every replica's requests: each replica writes its load with the
  500 ms poll (table `gantry_deployment_load`, migration 3 of namespace `gantry_routing`) and checks against the
  others' from memory, with no database call on the request path.

### Devices: MCP servers approved or blocked

- The self-hosted `/device/report` takes the agent's `os` and its `mcp` inventory and keeps them (migration 3 of
  namespace `enterprise.devices`: `enterprise_devices.os`, `enterprise_device_mcp`, `enterprise_mcp_decisions`). A
  target's query or login is stripped before it is stored.
- The Devices page lists every reported MCP server with its tools, devices, whether it goes through Gantry, and an
  Approve or Block button; `GET` and `POST /console/devices/mcp` do the same by API. Each decision is an admin record
  `device_mcp_decided`. The device profile carries the decisions (`mcp: {approved, blocked}`); the agent marks each
  server of its report and warns about blocked ones it finds configured.
- `gantry audit coverage --devices` prints each device's MCP servers, `via_gantry` and the decision.

### Routing resilience, continued

- Providers take `headers_env` (headers sent with every request, values from the environment) and `proxy_env` (an
  HTTP proxy its requests are tunnelled through with CONNECT, Basic credentials from the URL).
- Deployments take `max_parallel`, `rpm` and `tpm`: one at a limit is passed over, and with every deployment there
  the caller gets 429 `deployment_limit`.
- Key pools take a `weight` per key and `key_quarantine_seconds` (default 3600); aliases take
  `rate_limit_headroom_percent` (default 5).
- A request's own `fallbacks` field is honored for models the caller's rule allows; one it does not allow is refused
  with `model_not_allowed`. The field never reaches the provider.
- `gantry check` prints each alias's worst-case wait for the first byte across retries, timeouts and fallbacks.
- Health probes are written to the audit log as the workload `gantry-probe`, and a chat probe's cost is charged to the
  `gantry-probe` scope. With a store, one replica at a time probes each deployment (lease in `gantry_probe_leases`,
  migration 2 of namespace `gantry_routing`).

### An organization added by a reload is covered at once

- With `audit: { per_org: true }`, an organization a policy reload adds gets its chain opened when the reload is used,
  copied into the request index, exported, retained, held and shipped to the segments bucket from then on, with no
  restart. The chains of organizations open at start are now copied into the request index for the life of the
  gateway (their copier stopped after its first wait).

### Devices: verified people and bound devices

- The device agent sends the person's Gantry key from `gantry login` in `x-gantry-key`, and the gateway takes the
  person (and, without a team token, the team) from that key, never from the report. Reports without one are refused
  with `person_key_required`, with a bad key with `invalid_person_key`.
- A device is bound to the first person and token scope that reported it. Reports from another are refused with
  `device_bound` and listed on the Devices page under **Refused reports**. `DELETE /console/devices/devices/<id>`
  removes a device and its binding. New migration 2 in namespace `enterprise.devices`.
- The Devices page counts traffic from the store's shared request index (every replica), not this replica's audit log.

### Google's Gemini API

- Gantry serves Google's own Gemini API, so Gemini CLI (`GOOGLE_GEMINI_BASE_URL` and `GEMINI_API_KEY`) and Google's
  SDKs go through it: `POST /v1beta/models/<model>:generateContent`, `:streamGenerateContent` (with `alt=sse`, or
  as one JSON array without it), `:countTokens`, `:embedContent`, `:batchEmbedContents` (and the `/v1/` forms), and
  `GET /v1beta/models` and `/v1beta/models/<model>`, which list only what the caller's rule allows. Requests go as
  sent to `gemini` and `vertex` providers, with the rule, aliases, kill switches, observe mode, regions, guardrails
  on request and answer text (streamed too), budgets and limits from `usageMetadata` and
  `generationConfig.maxOutputTokens`, the cache and the audit record, user agent included.
- On those routes the Gantry key may come in `x-goog-api-key` or `?key=`. A query key is taken out before the
  request is checked: it is never forwarded, traced or recorded. Refusals there use Google's error shape. A body
  naming another model than the path is refused with `ambiguous_model`. An alias in the path is sent as its
  deployment, in the body too (countTokens' `generateContentRequest.model`).

### Routing resilience

- Timeouts per provider, alias and deployment: `timeouts: { connect_ms, first_byte_ms, total_ms, idle_ms }`, each
  looked up deployment, alias, provider, then the gateway's default (5 s, 120 s, 30 min, 5 min). A connect or
  first-byte timeout moves the request on and cools the deployment down; a total or idle timeout cuts the answer off
  and cools it down.
- Health probes: `probe: { every_seconds, with: models | chat }` on an alias's deployment checks it in the background
  and cools it down when it fails, shared through the store's cooldowns. Shown in `/readyz` under
  `checks.deployments` and as `gantry_deployment_up`.
- Key pools: `keys: [{ key_env }, { credential }]` and `key_balance: round_robin | least_used` on a provider. A key
  answered 401 or 403 is set aside for an hour, one answered 429 rests for its Retry-After; the request moves to the
  next key at once. Each switch is in the attempts record (`key`, a hash prefix) and
  `gantry_provider_key_switches_total`.
- Fallbacks: a provider's `fallback` chain is followed hop by hop (A, then B, then C). An alias's `fallbacks` and
  `fallback_on` (`rate_limit`, `server_error`, `timeout`, `unreachable`, `context_window`, `content_policy`) try
  other models or aliases in turn, across APIs (chat to messages and back, translated as sent). The caller's rule
  must allow each fallback by name.
- Conditional routing: `when:` on a deployment keeps it for requests by team, tag, customer, prompt size, tools,
  images or a header.
- Rate-limit-aware routing: a deployment whose provider says less than 5% of a rate limit is left goes after the
  others, under every balance (OpenAI `x-ratelimit-*`, Anthropic `anthropic-ratelimit-*`).
- `balance: adaptive` with `weights: { latency, errors, cost }`: p90 latency, a moving error rate and price, scaled
  and weighted.
- Wildcard models: `*` patterns in a provider's and a rule's `models`, and `<provider>/<model>` names. A budgeted
  request for an unpriced model is refused with `no_price`, so a pattern never escapes a budget.
- Answer headers: `x-gantry-request-id` on every answer, and `x-gantry-provider`, `x-gantry-model`,
  `x-gantry-deployment`, `x-gantry-attempts` and `x-gantry-cost-usd` on forwarded ones (a stream's cost is the
  prompt's estimate).

### Replicas share routing and the dry run

- With a store, session affinity pins and `lowest_latency` measurements are shared: every replica pins a coding
  agent's session to the same deployment and ranks deployments on the same pooled p90 time to first byte, read from
  memory and refreshed with the 500 ms poll (no database call per request). New tables `gantry_affinity` and
  `gantry_latency` in the migration namespace `gantry_routing`. Without a store, each gateway keeps its own, as before.
- The policy dry run (`POST /admin/policy/dry-run` and the console's **Dry run**) replays every gateway's requests from
  the store's shared request index, plus this gateway's not yet copied ones, each once. Without a store it replays
  this gateway's audit log. The result names its `source` (`store` or `audit_log`) and a `note`.

### JWT on the admin API

- `role_claim` on a `jwt:` issuer: its tokens sign in to the admin API with the first role whose `sso_values` holds one
  of the claim's values (for example `groups`). Records keep the issuer and subject, never the token. A token with no
  matching role is refused with `not_admin`.

### CI

- `scripts/console_edit_check.py` (the console's editing pages in a real Chrome) runs in CI as the `console-edit` job,
  against its own Postgres, and in `scripts/ci.sh` when `GANTRY_TEST_DATABASE_URL`, Chrome and `psql` are present.
  `--fresh` makes its own database.

### Batches, images and realtime

- Amazon Bedrock batch inference and Vertex AI batch prediction (Gemini, and Claude on Vertex AI) behind `/v1/files`
  and `/v1/batches`: a provider's new `batch: { bucket, role_arn, url, storage_url }` names the S3 or Cloud Storage
  bucket. Gantry checks and translates the lines, keeps the file in the bucket, starts the provider's job, answers
  status in OpenAI's shape, meters each result line at the batch price, and serves the results as OpenAI output and
  error files owned by the batch's creator. The provider is the model's deployment; a rule with `regions:` reaches an
  alias deployment labelled with one of them. New refusal codes `batch_not_configured`, `wrong_endpoint`,
  `provider_refused`.
- Batch results pass the batch owner's `on: [answer]` guardrails when downloaded (OpenAI output files, Anthropic
  message batch results): block replaces the line's answer with an error object, mask masks, and each line with a
  finding gets a `batch_result_guardrails` record.
- File uploads and batch creations count against `rpm` (rule, key and `limits:`), and a rule's new
  `batch: { max_lines, max_open }` refuses with `batch_too_many_lines` and `batch_too_many_open`.
- `POST /v1/images/edits` and `POST /v1/images/variations`: multipart forms decided on their `model` field, guarded on
  their text fields, reserved and charged per image (`n`).
- Realtime sessions charge audio and text tokens apart, from the providers' usage details, at the new price fields
  `input_audio`, `output_audio` and `cache_read_audio`. Usage records carry `input_audio_tokens`,
  `output_audio_tokens` and `cache_read_audio_tokens`.
- The price table from LiteLLM's map now carries audio token prices and batch prices (`batch_input`, `batch_output`,
  `batch_cache_read`); a batch line pays them where set, half the model's price where not.

### Budgets, alerts and audit chains per organization

- Sliding-window budgets: `budget: { usd: 300, per: { sliding: 24h } }` counts what was spent in the 24 hours before
  now, in 1,440 slots, and never starts again all at once. Exact across replicas with a store: every replica reserves
  against the same slots under a lock on the counter. Minutes, hours, days or weeks; `tz` is refused for one. The
  refusal says the budget slides. A calendar `per: 30d` is unchanged.
- Alerts: a `budget` rule with a **percent** fires when spend reaches that percent of each budget the policy sets for a
  scope (`team:payments`, `org:acme`, `customer:globex-shop`, or a kind alone for each one), in that budget's own
  period, calendar or sliding, read from the counter enforcement reserves against; with **Forecast**, when the
  current rate would reach it by the period's end. The dollar form is unchanged.
- `provider_errors` alerts count every request no provider answered, retried or not. The `upstream_error` record
  names the provider of the last try and how many tries there were (`provider`, `tries`).
- `audit: { per_org: true }` keeps each organization's records in a hash chain of its own
  (`gantry-audit.jsonl.orgs/<org>.jsonl`); records of no organization stay in the install's chain. `gantry audit
  verify` checks every chain, `--org <org>` one. People kept to an organization read its chain in the console, and
  others switch between chains. Retention, legal hold, audit export, alerts, the request log and segment shipping
  (under `orgs/<org>` in the bucket) work per chain. Gantry checks every chain at start.

### Devices and coverage

- Devices (enterprise, license feature `devices`): the self-hosted gateway now serves the device agent's
  `GET /device/profile` and `POST /device/report`, with enrolment tokens scoped to the install or one team, expiring
  (1 to 365 days) and revocable from the console's new Devices page or the admin API (`/console/devices/tokens`, an
  admin key as bearer). Profiles are per team. Reports, tools and drift are kept in Postgres (namespace
  `enterprise.devices`). The Devices page shows, per person, the tools seen in traffic, enrolled devices and each tool
  calling a provider directly.
- `gantry device` reports a state per tool (`not_installed`, `installed`, `gantry`, `direct`) and looks for Codex,
  Claude Code, Cursor, GitHub Copilot (VS Code and CLI), Zed, JetBrains AI Assistant, Qwen Code, Gemini CLI, Kilo Code,
  Roo Code and Claude Desktop, from each tool's documented configuration files only. It sends the person `gantry
  login` saved, so the gateway answers with their team's profile. Tool names now match `gantry audit coverage`
  (`github-copilot`, was `vscode`).
- `gantry audit coverage --devices devices.json` merges the device reports (downloaded from the Devices page) with
  the audit log: two more columns, `devices` and `direct`.
- MCP records (`/mcp`) carry `user_agent`, so MCP clients count in the coverage report.

### Supply chain and releases

- Published images are signed with cosign, keyless (the release workflow's GitHub identity, through Sigstore), and
  carry a CycloneDX SBOM and SLSA provenance as signed attestations. The Helm chart is published as a signed OCI
  artifact, `oci://ghcr.io/ggantry/charts/gantry`. `scripts/verify_release.sh X.Y.Z` checks the image, its SBOM and
  provenance, and the chart, and prints the digest to pin. Docs: Operations, Verify a release.
- The binary records its exact crate list inside itself (cargo-auditable), so `syft`, `grype` and `cargo audit bin`
  read the dependencies of the image and of any release binary.
- Every image CI builds is scanned (syft and Grype); a high or critical vulnerability fails the build unless
  `.grype.yaml` allows it with a reason. CodeQL analyzes the Rust code and workflows on every pull request.
- No FIPS build yet: the Verify a release page says why (ring, not a validated module, does TLS and signing) and what
  one would take.

### Docker first start

- `docker run -v gantry-data:/var/lib/gantry -e OPENAI_API_KEY ghcr.io/ggantry/gantry` with no policy starts a
  working gateway in observe mode, with an admin key printed once and the tool settings, as `gantry start` does.
  Later starts serve what the first one wrote. The image's default command is now `start --container`; a policy
  mounted at `/etc/gantry/gantry.policy.yaml` is served as before, and explicit `serve ...` commands (Compose, Helm,
  Terraform) are unchanged.
- `gantry start` with `--listen 0.0.0.0:<port>` prints `http://localhost:<port>` in the tool settings, not an address
  a browser cannot open.

### Helm

- `autoscaling.enabled` renders a HorizontalPodAutoscaler on CPU and an optional per-pod custom metric (for example
  from `gantry_overhead_seconds`); it needs `store:` in the policy, as more than one replica always did. A
  PodDisruptionBudget (`maxUnavailable: 1`) is rendered with more than one replica or with autoscaling.

### Rolling upgrades

- Two versions one minor version apart now run on one Postgres at the same time: the newer applies its migrations
  while the older keeps serving, and an older replica restarting mid-rollout still starts. A version two or more minor
  versions behind refuses the database, naming both versions. Store migration 6 adds the `gantry_writer` table, which
  records the newest version that started on the database. Versions released before this one refuse any newer schema
  at restart, so for the upgrade to this version keep old pods from restarting during the rollout.
### Identity

- SAML 2.0 sign-in to the console (`console.saml`), beside OpenID Connect: service provider metadata at
  `/console/saml/metadata`, requests by HTTP-Redirect and answers by HTTP-POST at `/console/saml/acs`. Only signed
  assertions are taken (enveloped signatures, exclusive canonicalization, SHA-256 or SHA-512 with RSA or ECDSA),
  verified against `idp_certificate` (two certificates during a rotation); wrong audience, recipient or issuer,
  expired, replayed, unstarted, encrypted and wrapped assertions are refused and recorded (`saml_*` codes). Groups
  give roles (`admin_values`, `read_only_values`, roles' `sso_values`) and teams.
- Teams as a policy object: `teams:` with `owner`, `members` by email, `sso_values` and `metadata`, listed beside
  the teams keys name. `GET /admin/teams` and `GET /admin/teams/<name>`; `POST`, `PUT` and `DELETE` save a new policy
  version when the policy is kept in the store. The console's Teams page shows owners.
- `gantry login` puts a developer's key in their team: the team that lists their email, else the first whose
  `sso_values` match their `role_claim` values, else `self_issue.team`. When `teams:` places people and places this
  one nowhere, and `self_issue.team` is not written, the login is refused with `sso_team`.
- Console roles kept to teams (`teams:`) or end customers (`customers:`), as `org:` keeps one to an organization: in
  the console and the admin API their holders see, issue, change and revoke only those keys, and see only those
  audit records, requests, analytics and spend. They cannot set kill switches, change credentials, the policy or
  teams.
- Setup guides for Okta, Microsoft Entra ID, Google Workspace, OneLogin, Keycloak and JumpCloud, for OpenID Connect
  and SAML.
- `gantry login` over SAML: on a setup with `console.saml` and no `console.sso`, `gantry login` opens the SAML
  sign-in and the browser comes back to the CLI's listener on 127.0.0.1 with a one-use code, traded for the key with
  the PKCE verifier, as with OpenID Connect. Turned on by `console.saml.self_issue` (same fields as
  `console.sso.self_issue`); groups place the key in a team the same way.
- `console.sso.scopes`: the scopes asked for at the authorization endpoint, `openid email profile` unless set (must
  include `openid`). Okta's org authorization server and OneLogin send a `groups` claim only when `groups` is asked
  for; their guides now use `scopes: openid email profile groups`.
- An ID token whose `iss` is `accounts.google.com` is taken for `issuer: https://accounts.google.com`, as Google
  documents both forms.
- The identity provider guides were checked against each vendor's current documentation: Okta's Classic experience
  step and legacy group statements, JumpCloud's response-only signing default and SSO IdP URL, Entra's direct
  membership rule for groups assigned to the app, Google's one-time client secret and Audience page, Keycloak's PKCE
  setting before 26.3, OneLogin's parameter labels. Details the vendors do not document are marked.

### Secrets

- Secret managers in `gantry serve` (enterprise feature `secrets`): a variable the policy names with `*_env` may hold
  `vault://<path>#<field>`, `aws-sm://<name>`, `gcp-sm://projects/<p>/secrets/<s>` or `azure-kv://<vault>/<secret>`.
  Each is read at start (a failure stops the start, naming the variable), kept in memory, and read again every
  `GANTRY_SECRETS_REFRESH_SECONDS` (300) and on SIGHUP; a rotated provider key is used for new requests within a
  second. Each manager signs in with its platform's chain (Vault token or Kubernetes auth, the AWS default chain,
  Application Default Credentials, Entra client secret, workload or managed identity). Without the feature a
  reference stops the start with the fix, and is never sent as a key.
- Each secret a refresh finds rotated writes a `secret_rotated` audit record, and each one it cannot read a
  `secret_refresh_failed` record (code `secret_refresh_failed`, with the reason): the variable, its reference and the
  manager, never the value. Counted in `/metrics` as `gantry_secret_rotations_total` and
  `gantry_secret_refresh_failures_total` by manager. With the `alerts` feature, a **system** alert rule fires on a
  failed refresh.
### Operator API and metrics

- `GET /admin/usage`: spend, tokens and requests grouped by `org`, `team`, `person`, `key`, `customer`, `tag`,
  `model`, `provider`, `agent`, `day` or `hour`, filtered by time range and any dimension, as JSON or CSV. Summed in
  SQL by the store's request index, else from the gateway's audit log. Needs `see_spend`; a role kept to an
  organization sees its own.
- The admin API covers what the console does: providers, rules, guardrails, MCP servers and aliases a part at a time
  (`/admin/<part>[/<name>]`), models and prices (`/admin/models`), budgets (`/admin/budgets`, the `limits:` list) and
  teams (`/admin/teams`). Each change is a new policy version with its admin record, as `PUT /admin/policy` makes.
- `GET /admin/openapi.json`: an OpenAPI 3.1 document of every admin route, its permission and record action. Routes
  and document come from one table; any path not in it is refused with `unknown_route` and recorded as an `admin`
  record.
- `/metrics` adds `gantry_tokens_total` (input, output, cached, cache_write), `gantry_request_seconds`,
  `gantry_first_byte_seconds`, `gantry_refusals_total`, `gantry_guardrail_findings_total`,
  `gantry_cache_lookups_total`, `gantry_deployment_up`, `gantry_deployment_cooldowns_total`,
  `gantry_budget_limit_usd`, `gantry_budget_remaining_usd` and `gantry_store_up`. Labels come from the policy only;
  `GANTRY_METRICS_BUDGET_SCOPES` chooses the budget scopes shown (default `global,org,team,model`).
- Alerts (enterprise): `unusual_requests`, `unusual_errors` and `unusual_latency` against a 14-day baseline per
  team, key or provider; `deployment_down`, `key_expiring`, `credential_failing`, `guardrail_vendor_failing` and
  `export_lagging`. Alert rules are in the admin API (`/admin/alerts/rules`), and an embedding binary adds admin routes
  through `gantry_server::AdminApi`, checked and recorded by the gateway.
- Alerts (enterprise): `daily_digest` (per rule's channels, at a local time, the last 24 hours of spend, refusals,
  top users and alerts), `region_outage` (every alias deployment of a `region:` failing with none answering),
  `config_rejected` (a reload refusing a policy or keys change, or a policy version refused as `invalid_policy`),
  `kill_cleared` and `circuit_open` (an alias deployment put to cool down).
- `/admin/usage`, `/admin/teams` and the policy-changing routes honor roles kept to teams or end customers (`teams:`
  and `customers:` on a role) as they do roles kept to an organization.
- `gantry import litellm --url <proxy> --master-key-env <VAR>` reads a running LiteLLM proxy's model list, keys and
  teams through its management API, writes team budgets as `limits:`, and issues one Gantry key per LiteLLM key into a
  new keys file, printing each beside the key it replaces.
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
  for an hour, when the request says `"store": true`.
- Async jobs: `POST /v1/async/<route>` runs a model request in the background on the governed route and
  `GET /v1/async/<route>/<id>` reads its answer, held for its submitter for an hour (`x-gantry-async-ttl`).
- Azure: images, transcription, speech and legacy completions on deployment paths, and the v1 API (a `url` ending in
  `/openai/v1`, no `api_version`), with images and audio sent to its preview.
- Vertex AI and the Gemini API count a Gemini model's tokens (`countTokens`) for `POST /v1/messages/count_tokens`.
- Native kinds `sagemaker` (SageMaker endpoints with an OpenAI-shaped container, signed with SigV4, streams included)
  and `replicate` (predictions translated from chat, waited for and cancelled after 60 seconds). Presets `sagemaker`,
  `replicate`, `oci` (OCI Generative AI, API key) and `triton` (Triton's OpenAI-compatible frontend).
- A Bedrock stream through signed passthrough is charged the usage its events report, not its reservation.
- With a store, async job answers and translated responses kept with `store: true` are kept in Postgres (table
  `gantry_batches_held`, namespace `batches`, migration 2), sealed under the master key when there is one, so any
  replica answers for them; without a store they stay in the memory of the replica that took them.
- Background responses (`background: true`): the queued answer charges nothing and keeps its reservation; what the
  response used is charged once, the first time Gantry sees it ended (read by its creator, cancelled, deleted, or polled
  once a minute), on one replica only with a store.
- Replicate streams live: `stream: true` creates the prediction with `"stream": true` and passes each event of its
  `urls.stream` on as a chat chunk, with usage read from the prediction when it is done. Input fields follow each
  model family's schema on Replicate (Meta, IBM Granite, Anthropic, Google, OpenAI), and a field a family has no
  place for is refused by name. **Changed:** `temperature`, `top_p`, `seed` and `stop` to an Anthropic model on
  Replicate, and `seed` and `stop` to a Google or OpenAI one, are now refused instead of sent.
- OCI Generative AI request signing: `oci_signing` (tenancy, user, fingerprint, and `key_file` or `key_env`) signs
  each request with an OCI API signing key, in place of an API key.
- Triton's generate extension through passthrough (`/v2/models/<model>/generate` and `/generate_stream`): the model
  is decided from the path and metered from its `num_input_tokens` and `num_output_tokens` when it reports them; an
  unpriced one under a budget is refused with `no_price`.
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
- Function tool permissions: `function.<name>` and `!function.<name>` entries in a rule's `tools:` decide the function
  tools a request declares (OpenAI `tools` and `functions`, Responses, Anthropic, Gemini `functionDeclarations`) and
  the tool calls in an answer. `tool_action: block` (default) refuses with `tool_not_allowed`; `strip` takes them out.
  Each is recorded by tool name, never with its arguments. `!` deny entries work for MCP tools too. An MCP server can
  no longer be named `function`.
- MCP tools narrowed per key (`mcp_tools:` in the keys file and the admin API) and per request (the
  `x-gantry-mcp-tools` header). Both only narrow the rule's `tools:`, never widen it.
- Answer guardrails read tool call arguments in every format: Anthropic `tool_use` input, Responses `function_call`
  arguments and Gemini `functionCall` args, besides chat `tool_calls`. Request guardrails read Gemini `contents` and
  `systemInstruction` text.
- `pack: gitleaks` on a `secrets` guardrail: Gitleaks' default rule set (221 rules, MIT, attributed in
  `crates/gantry-core/data/GITLEAKS-LICENSE`), measured at 97.2% precision and 84.9% recall on the detector corpus.
- Six more vendors: `pangea`, `nemo_guardrails`, `hiddenlayer`, `lasso`, `guardrails_ai` and `aporia`.
- Transforms: `type: transform` services and the `Transform` extension hook rewrite the request before it is checked
  and sent and the answer before it is checked and returned. Each change is recorded as a diff summary of JSON paths
  under `transforms`. A request transform may not change `model` or `stream`; a failing one follows `on_failure`
  (`transform_failed`).
- Guardrails on realtime sessions: the caller's text events are dropped (or masked) when a guardrail blocks, a blocked
  transcript of what was said ends the session, and the session record lists the findings.

### Integrations

- LangChain guide (Python and JavaScript) and `scripts/langchain_check.py`, which drives LangChain against a local
  Gantry. The Cursor guide gains a quick tunnel setup and a test of the requests Cursor's docs describe; Cursor itself
  is not run.

### Device agent

- `gantry device` runs on Linux (root systemd unit, `deploy/mdm/gantry-device.service`) and Windows (a logon task),
  with each tool's paths on each OS. Each report lists the MCP servers configured in Claude Desktop, Claude Code,
  Cursor, VS Code and Zed, and whether each goes through Gantry's MCP gateway.

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
