# Comparison with LiteLLM and Bifrost

LiteLLM and Bifrost are the two open source AI gateways teams most often compare Gantry with. This page compares Gantry 0.0.1 with LiteLLM v1.109.1 and Bifrost v2.5.1 (open source editions), from a hands-on review run on 2026-11-12 and from their public documentation. No source code of either project was read. Measurements were taken on one laptop and are not benchmarks.

Gantry is much younger and does much less. The comparison says so first.

## What each does better

### LiteLLM does better

- **Providers.** It supports over 140 providers and translates between their APIs; Gantry forwards to OpenAI-compatible servers (with a documented base URL for Groq, Mistral, Together, Fireworks, DeepSeek, OpenRouter, Ollama, vLLM and LM Studio), Anthropic, Azure OpenAI, Bedrock (Claude), Claude on Vertex AI, and Gemini and Vertex AI through the chat route, translated; Claude Code reaches chat providers (GPT, Gemini, local models) through messages-to-chat translation. It has no Cohere, no Bedrock models other than Claude, and no batch or files routes (images, audio, moderations and rerank are forwarded).
- **Spend control.** Budgets per key, team and organization, rate limits with `retry-after`, spend tracking per request. Gantry has budgets per team, person or key (reserved at admission, settled from each answer's usage), requests per minute per person and tokens per minute per person, team or key, with `Retry-After`, a cost on every usage record priced from a built-in table of about 7,000 models, and an exact-match cache; it has no budget per organization or tag yet.
- **Time to a first request.** 8 seconds from `docker run` with a five-line config and no database, measured in the review. Gantry's image answers its first governed request within a second of `docker run`, but needs a policy file and a key first.
- **Virtual keys by API**, created with one call, with model allowlists, budgets and limits. Gantry keys are issued with one call to its admin API, in the console or on the command line, and work within 2 seconds; a key can carry an expiry, a budget, a tokens-per-minute limit and a model list that narrows its rule, each settable by the admin API, `gantry key new` or the keys file.
- **Routing breadth.** LiteLLM has more routing strategies (latency and cost based) and shares cooldowns across instances through Redis. Gantry has aliases over several deployments with weighted round robin or least busy, cooldown per process, retries, a provider fallback, and named fallbacks on context window and content policy errors.
- **An admin UI** and client guides for many coding agents (Claude Code, Codex, Cursor, Gemini CLI and others). Gantry has a small admin console (audit log, people and keys, policy, spend) and guides for Claude Code, Codex CLI and OpenCode (each run through Gantry against a mock provider), and for Cursor, Continue, Cline, Aider and the OpenAI and Anthropic SDKs (written from each tool's docs, not run), no Gemini CLI guide.
- **Fails closed on a database outage** by default, as Gantry does on an audit failure.

### Bifrost does better

- **Speed of forwarding with features on.** About 1 ms added at p50 in the review's Docker setup, with routing, budgets and logging.
- **Governance objects in open source.** Customers, teams and virtual keys with budgets and rate limits, and immediate key deactivation through its API.
- **More APIs.** It translated `/anthropic/v1/messages` and `/v1/responses` to a chat-only server. Gantry forwards `/v1/responses` and `/v1/embeddings` to OpenAI-compatible providers as sent, translates chat requests for Gemini and for Claude providers that opt in, and refuses a messages or Responses request to a provider that does not speak it.
- **MCP gateway** with tool filtering per virtual key, deny by default. Gantry has nothing for MCP.
- **Response headers** naming the provider and resolved model, and a latency split per request in its log.
- **Coding-agent guides** for 13 tools, and a device product for laptops (enterprise).

### Gantry does better

- **A record before every request, in the free edition.** Every request, allowed or refused, gets a hash-chained audit record before it is forwarded, and `gantry audit verify` checks the chain. LiteLLM writes no audit rows without an enterprise license, and its audit log covers admin changes, not requests. Bifrost's audit log, with an HMAC per row, is enterprise only.
- **Fail closed on the record.** If the record cannot be written, the request is refused. In the review, LiteLLM kept forwarding while its per-request spend rows went missing for 6,498 load-test requests.
- **Unknown config is an error.** `gantry check` names the file, line and nearest known word for every mistake. Both others accept misspelled keys silently and start.
- **Nothing dropped silently.** The body is forwarded byte for byte and an unknown query parameter is refused by name. LiteLLM removed the standard `user` and `metadata` fields; Bifrost dropped an unknown parameter.
- **Keys shown once, stored hashed.** Bifrost's list API returns every key's full value on every read.
- **No prompt text in the log.** Bifrost stores prompts and answers by default for 365 days.
- **Small footprint.** A {{IMAGE_SIZE}} image running as a non-root user, about 3.4 MiB of memory at idle. LiteLLM's image is 1.33 GB and runs as root, using 628 to 922 MiB plus Postgres; Bifrost's is 286 MB using 219 to 442 MiB.
- **Refusals a person can act on.** Each names the cause, the fix and a decision ID, in the error shape the client already shows.

## Side by side

| | Gantry 0.0.1 | LiteLLM v1.109.1 | Bifrost v2.5.1 |
|---|---|---|---|
| Language | Rust | Python, routing moving to Rust | Go |
| Storage | files | Postgres for keys and budgets | SQLite or Postgres |
| Image, user | {{IMAGE_SIZE}}, uid 65532 | 1.33 GB, root | 286 MB, uid 1000 |
| Memory, measured | 3.4 MiB idle | 628 to 922 MiB | 219 to 442 MiB |
| Identity per request | Gantry key per person or workload | virtual key | virtual key |
| Policy | file, first matching rule by team, person or anyone | per key, team, org via API | per key, team, customer via API |
| Budgets, rate limits | budgets per team, person or key; requests per minute per person, tokens per minute per team, person or key | yes | yes |
| Aliases, load balancing | aliases over deployments, weighted round robin or least busy, cooldown, context window and content policy fallbacks; rules decide on the alias | yes, more strategies | yes |
| Guardrails | open source: built-in secrets and personal data (block, mask, warn); OpenAI moderation, Presidio (mask through its anonymizer), Lakera Guard, Bedrock guardrails (SigV4), Azure Content Safety and Prompt Shields, and Llama Guard or any chat model as a classifier, built in, each with fail open or closed and a credential from the environment; any other service through a webhook contract. On requests, and on whole answers with `on: [answer]` (block, mask, warn, each with its own record); streamed answers are not checked | yes, some enterprise | enterprise |
| Request audit log in open source | yes, hash-chained, verified at start | no | no (request log, not tamper-evident) |
| Unknown config keys | refused with line and suggestion | accepted silently | accepted silently |
| Unknown request parameters | forwarded unchanged; unknown query refused | some standard fields dropped | dropped |
| Providers | OpenAI chat completions, Responses, embeddings, images, audio (transcriptions and speech), moderations and rerank, Anthropic messages, Azure OpenAI, Bedrock for Claude, Claude on Vertex AI, Gemini and Vertex AI; chat translated to messages (per provider) and to Gemini, messages translated to chat and Gemini (per provider, for Claude Code) | 140+, translated | many, translated |
| SSO, roles | open source: console sign-in by OpenID Connect (PKCE, RS256 and ES256), admin and read-only roles from a claim, every sign-in recorded; SAML and SCIM planned | SSO free to 5 users, then enterprise | enterprise |
| Developer sign-in for coding tools | `gantry login`: SSO in the browser, personal key named by the email, expiry from policy, recorded; `gantry logout` revokes it | UI login, keys copied by hand | enterprise |
| Kill switch | person, team, key, model or everyone, reason required and shown to the caller, within 1 second on every node sharing the files, recorded | no (block a key or team by API) | no |
| Metrics | Prometheus `/metrics` on its own address, off by default; audit log as JSONL for any log shipper | Prometheus, many callbacks | Prometheus, OpenTelemetry |
| Multi-node | no | yes, Redis for shared limits | enterprise clustering |

## Sources

The figures above come from the hands-on review in the project's research notes (2026-11-12), which ran both products locally in Docker against a mock provider, and from these pages:

- https://www.litellm.ai/pricing
- https://docs.litellm.ai/docs/proxy/audit_logs
- https://docs.litellm.ai/docs/proxy/admin_ui_sso
- https://docs.getbifrost.ai/enterprise/audit-logs.md
- https://www.getmaxim.ai/bifrost/pricing
- https://docs.getbifrost.ai/mcp/filtering.md
