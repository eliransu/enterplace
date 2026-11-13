# Overview

Gantry is an AI gateway where governance comes first. It sits between the tools your people and workloads use (Claude Code, OpenAI-compatible clients, your own agents) and the model providers. Every request that reaches it gets three things before it leaves:

1. **A person.** The caller sends a Gantry key, not a provider key. The key names a person or a workload and their team.
2. **A policy decision.** A policy file says which team or person may use which model. Gantry decides by the first rule that names the caller.
3. **An audit record.** One line in a hash-chained log, written before anything is forwarded. A request that cannot be recorded is refused.

Only then is the request sent to the provider, with the provider's key in place of the caller's.

Gantry is open source under Apache 2.0. It is one binary with no database: the policy, the keys and the audit log are files.

## Status

Version 0.0.1. One node, with an admin console at `/console`. What this version does is listed below; anything marked planned or not built yet in these pages does not exist in the binary.

| Built today | Not built yet (planned) |
|---|---|
| Gantry keys per person and workload (`gantry key new`, the admin API, the console), with an optional expiry, budget, model list and tokens-per-minute limit per key; the first admin made with `gantry key new --admin` | SAML sign-in and SCIM provisioning |
| A policy file of rules by team, person or anyone, checked by `gantry check`; kill switches with a reason (`gantry kill`, `gantry unkill`) | |
| `gantry login` and `gantry logout`: a developer's own key through single sign-on, with an expiry | |
| Guardrails on each rule: built-in secrets and personal data detectors, seven guardrail vendors, and outside services by webhook, on requests and on answers (whole answers always; streamed answers when the rule sets `buffer_stream: true`) | Spend in more than one node |
| Usage and cost of every answer with prices built in for most models (`gantry prices`), budgets per team, person or key, requests and tokens per minute, and a cache per rule | Budgets per organization or tag |
| `POST /v1/chat/completions` to providers that speak the OpenAI chat completions API, Azure OpenAI included, and to Gemini and Vertex AI, translated | |
| `POST /v1/responses` and `POST /v1/embeddings` to OpenAI-compatible providers, as sent | Other Responses routes (`GET`, `DELETE`, cancel) |
| `POST /v1/messages` and `/v1/messages/count_tokens` to providers that speak Anthropic's messages API, and `/v1/messages` to Claude on Amazon Bedrock and Claude on Vertex AI (`vertex_anthropic`) | `count_tokens` for Bedrock, Vertex AI and translated models |
| Claude Code to GPT, Gemini or a local model: messages requests translated to chat completions for a provider with `accept_messages: true` | Translation from the Responses API to chat completions providers |
| `GET /v1/models`: Anthropic's list for Claude Code, OpenAI's list for other callers | Cursor, Continue, Cline and Aider not yet run through Gantry (their guides follow each tool's docs) |
| A hash-chained audit log and `gantry audit verify`, with Vector, Fluent Bit and OpenTelemetry Collector examples for shipping it | More than one node |
| Prometheus `/metrics` on an address of its own (`--metrics`), off by default | OpenTelemetry traces |
| Reloading the policy and keys files without a restart, within 2 seconds | Export of the audit log to a SIEM |
| Retries and one fallback per provider, model aliases over several deployments (weights, cooldown, context window and content policy fallbacks), chat requests translated for Claude providers that opt in | |
| Images, audio transcription and speech, moderations and rerank routes to OpenAI-compatible providers | Batches and files |
| `gantry import litellm`: a policy from a LiteLLM proxy config ([Moving from LiteLLM](migrate-litellm.html)) | |
| An admin console: audit log, people and keys, policy, spend; sign-in by admin key or OpenID Connect single sign-on with admin and read-only roles | |
| A container image of {{IMAGE_SIZE}}, non-root (CI defined in `.github/workflows/ci.yml`, not yet run on a hosted service) | Retries across more than one fallback |
| Plain HTTP on loopback by default, or HTTPS with `--tls-cert` and `--tls-key` | Certificate reload without a restart |
| A Helm chart and plain Kubernetes manifests for one replica, and guides for Cursor, Continue, Cline, Aider, OpenCode and the OpenAI and Anthropic SDKs | |

## How a request flows

```text
client (Claude Code, Codex, curl, an agent)
   |  Authorization: Bearer gantry_...   or   x-api-key: gantry_...
   v
Gantry
   1. identify    the key's SHA-256 is looked up in gantry.keys.yaml      -> no_key, ambiguous_key, unknown_key
   2. route       is the method and path one Gantry serves?               -> unknown_route
   3. read body   within 32 MiB, 30 seconds and the memory budget         -> body_too_large, body_timeout, busy, unreadable_request
   4. decide      the first rule naming the person or team decides         -> no_rule, model_not_allowed
      kill        a kill switch on the person, team, key or model         -> killed
   5. provider    the one provider that lists the model, of the right kind -> unknown_model, wrong_route, untranslatable
   6. query       only parameters the route allows                         -> unknown_query
   7. guardrails  the rule's guardrails, built-in first, then webhooks    -> guardrail_blocked
   8. cache       a rule's cache answers an identical request here
   9. rate        requests per minute per person, tokens per minute      -> rate_limited
  10. budget      the most the request could cost is reserved             -> budget_exceeded
  11. record      one audit line, chained to the one before               -> audit_unavailable
  12. forward     provider key in, caller key out, retries and fallback   -> upstream_unreachable, upstream_failed, upstream_timeout
   v
provider (OpenAI, Anthropic, Azure OpenAI, Bedrock, a local model server)
```

Step 11 happens for every request, including the ones refused at an earlier step: a refusal is recorded too, with the code that refused it. A cache hit is recorded at step 11 and answered without step 12. When the answer ends, a usage record with its tokens and cost follows. Why guardrails come before the cache: [Policy file](policy.html#order-on-the-request-path). Every response carries an `X-Gantry-Decision` header with the decision ID, and every refusal repeats that ID in its message, so a person can quote it and an admin can find the record.

What Gantry sends to the provider is the request body exactly as it came, except where the policy says otherwise: a guardrail that masks, a chat request translated for a provider with `accept_chat`, and the body Bedrock takes. The provider's answer, including a streamed one and including the provider's own errors, comes back as the provider sent it, with `X-Gantry-Decision` added, except when it is translated back for a chat client or from Bedrock's event stream.

## Where to go next

- [Quickstart](quickstart.html): run it from source or as a container.
- [Policy file](policy.html): every key, with the errors `gantry check` gives.
- [Claude Code](claude-code.html): point Claude Code at Gantry.
- [Codex](codex.html): point Codex CLI at Gantry through the Responses route.
- [Refusal codes](refusals.html): what each code means and how to fix it.
- [Security model](security.html): what is protected and what is not.
