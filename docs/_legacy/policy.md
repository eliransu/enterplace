# Policy file reference

The policy file says which providers Enterplace forwards to and who may use which model. `enterplace check` and `enterplace serve` read it the same way, so a file that passes one is accepted by the other. Any key Enterplace does not know is an error, never ignored.

## A complete example

```yaml
# Who may use which model.
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_PROVIDER_KEY
    models: [gpt-4o-mini, gpt-4o]
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-5-5, claude-haiku-5-5]
  - name: local
    kind: openai
    url: http://127.0.0.1:11434
    allow_private: true
    key_env: OLLAMA_KEY
    models: [gpt-oss:20b]
guardrails:
  - name: no-secrets
    type: secrets
    action: block
  - name: mask-pii
    type: pii
    action: mask
rules:
  - name: maya-only
    principals: { name: maya.cohen }
    models: ["*"]
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini, claude-sonnet-5-5, claude-haiku-5-5]
    guardrails: [no-secrets, mask-pii]
    budget: { usd: 2000, per: month }
    rate: { rpm: 600 }
    cache: { ttl_seconds: 300 }
  - name: everyone-else
    principals: { any: true }
    models: []
prices:
  gpt-oss:20b: { input: 0, output: 0 }
audit: { path: /var/lib/enterplace/enterplace-audit.jsonl }
```

## Top level

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | Must be `1`. |
| `providers` | yes | The list of providers. At least one. |
| `rules` | yes | The list of rules, read in order. May be empty, which refuses everyone with `no_rule`. |
| `audit` | no | `{ path: <file> }`. Where the audit log is written. Default: `enterplace-audit.jsonl` beside the policy file. |
| `guardrails` | no | The guardrails rules may name. See [Guardrails](#guardrails). |
| `prices` | no | Prices by exact model name, over the built-in table. See [Prices](#prices). |
| `aliases` | no | Model names served by one or more deployments, with load balancing and fallbacks. See [Aliases](#aliases). |
| `console` | no | `{ sso: ... }`. Console sign-in through an OpenID Connect identity provider, read when someone signs in, no restart needed. See [Security model](security.html). |

## Providers

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Letters, digits, `.`, `-`, `_` and `@`, up to 100 characters. Unique. The audit record names the provider that served each request by this name. |
| `kind` | yes | `openai` (chat completions, Responses and embeddings), `anthropic` (messages and count_tokens), `azure` (Azure OpenAI chat), `bedrock` (Claude on Amazon Bedrock, messages), `gemini` (Gemini API, chat translated), `vertex` (Gemini on Vertex AI, chat translated) or `vertex_anthropic` (Claude on Vertex AI, messages). Routes, keys and examples per kind: [Providers](providers.html). |
| `url` | yes | The base URL, `http://` or `https://`, with no query, fragment or login. It may carry the vendor's path, such as `https://api.groq.com/openai/v1`: the route after `/v1` is added to it. Without a path, the whole route is added: a chat request goes to `<url>/v1/chat/completions`. A trailing `/` is removed. A `vertex` url ends in `/publishers/google`, a `vertex_anthropic` one in `/publishers/anthropic`. |
| `key_env` | yes, except as below | The name of the environment variable that holds the provider key. Letters, digits and `_`. `enterplace serve` refuses to start if it is unset or empty. An `openai` provider with `allow_private: true` may leave it out and is sent no key. A `bedrock` provider has none: it signs with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. |
| `models` | yes | The exact model names this provider serves. Not empty, no `"*"`. A model may be listed by one provider only. |
| `retries` | no | 0 to 5. Tries the same provider again after a connection failure, a timeout, a 429 or a 5xx, before any byte of the answer reaches the caller. Default 0. |
| `fallback` | no | The name of another provider of the same API to try when this one still fails after its retries. |
| `accept_chat` | no | `anthropic`, `bedrock` and `vertex_anthropic` only: `true` also takes chat completions requests for its models, translated to messages. |
| `accept_messages` | no | `openai`, `azure`, `gemini` and `vertex` only: `true` also takes messages requests (Claude Code) for its models, translated to chat completions and back. See [Providers](providers.html#translation-for-claude-code). |
| `deployments` | `azure` only | Model name to Azure deployment name. |
| `api_version` | `azure` only | The Azure OpenAI `api-version`. |
| `region` | `bedrock` only | The AWS region, for example `us-east-1`. |
| `model_ids` | `bedrock` only | Model name to Bedrock model ID. |
| `allow_private` | no | `true` lets `url` point at this machine or a private network (`localhost`, `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, link-local, `::1`, `fc00::/7`, `fe80::/10`, IPv4-mapped IPv6 of any of these, a trailing dot, and numeric spellings such as `127.1` or `2130706433`). Default `false`. |

The provider key is sent as `Authorization: Bearer <key>` to an `openai` or `vertex` provider, as `x-api-key: <key>` to an `anthropic` provider, as `api-key` to `azure` and `x-goog-api-key` to `gemini`.

Avoid naming a key variable `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` if the same shell runs the clients: Claude Code reads `ANTHROPIC_API_KEY` for its own key, which should be a Enterplace key.

## Rules

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Letters, digits, `.`, `-`, `_` and `@`. Shown in refusals and audit records. |
| `principals` | yes | Exactly one of `{ team: <team> }`, `{ name: <person or workload> }` or `{ any: true }`. |
| `models` | yes | Exact model names, `["*"]` for every model, or `[]` for none. `"*"` must stand alone. |
| `guardrails` | no | Names of guardrails defined under the top-level `guardrails:`, run in this order on every request the rule allows. A name that is not defined is an error. |
| `budget` | no | `{ usd: <dollars above 0>, per: day \| month }`. See [Budgets](#budgets). |
| `rate` | no | `{ rpm: <1 to 1000000>, tpm: <1 to 1000000000> }`, either or both: requests per minute per person, and tokens per minute counted where a budget is. See [Rate limits](#rate-limits). |
| `cache` | no | `{ ttl_seconds: <1 to 86400> }`: serve the same answer again for the same request. See [Cache](#cache). |
| `buffer_stream` | no | `true` holds a streamed answer whole so the rule's `on: [answer]` guardrails check it before the caller sees any of it, at the cost of the time to the first token. Needs a guardrail with `on: [answer]`. See [Guardrails](guardrails.html#checking-the-answer). |

Rules are read top to bottom and **the first rule that names the caller decides**. Later rules are not consulted, even if they would allow the model. A caller no rule names gets `no_rule`. A caller whose first rule does not list the model gets `model_not_allowed`, and the message lists what that rule allows.

In the example above, `maya.cohen` of team `payments` may use any model, because `maya-only` comes first. Everyone else in `payments` gets the three models listed. Everyone else gets nothing, with a message that says so.

A model a rule allows must still be served by a provider, or the request is refused with `unknown_model`.

## Guardrails

A guardrail checks the text of a request the policy has allowed, before the request is recorded and sent. On `/v1/chat/completions` and `/v1/messages` it reads the system prompt, every text message or text block, the text in tool results, text documents (`document` with a `text` or `content` source) and search results. On `/v1/responses` it reads `instructions`, every `input` text (a string, or the `input_text` parts of input messages), the `output` of `function_call_output` items, and the string values of `prompt.variables`. On `/v1/embeddings` it reads `input` strings; token ID arrays are not text and are not checked. Tool definitions, tool arguments, images and files (a PDF or any base64 document) are not read. See [Security model](security.html) for what this does and does not catch.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Letters, digits, `.`, `-`, `_` and `@`. Unique. Refusals and records name the guardrail by it. |
| `type` | yes | `secrets` or `pii` (built in, checked in Enterplace), a vendor (`openai_moderation`, `presidio`, `lakera`, `bedrock_guardrail`, `azure_content_safety`, `azure_prompt_shield`, `llama_guard`; their keys are in [Guardrails](guardrails.html)), or `webhook` (an outside service, see [Guardrail webhooks](guardrail-webhook.html)). |
| `on` | no | `[request]` (the default), `[answer]` or `[request, answer]`: what the guardrail reads. See [Guardrails](guardrails.html#checking-the-answer). |
| `action` | yes for `secrets` and `pii` | `block` refuses the request with `guardrail_blocked`. `mask` replaces each finding with `[MASKED <kind>]` and forwards the changed request. `warn` forwards the request unchanged. Every action records what was found. A `webhook` takes `block` (obey the service, the default) or `warn` (record its answer only). |
| `url` | webhooks and vendors | `https://`, or `http://` on `localhost`, `127.0.0.1` or `[::1]`. |
| `timeout_ms` | no, webhooks and vendors | 1 to 30000. Default 1000. Every request the rule allows waits up to this long. |
| `on_failure` | webhooks and vendors, required | `fail_closed` refuses the request when the service is down, slow, answers with an error status or sends a malformed answer. `fail_open` forwards it and records `skipped`. |
| `headers_env` | no, webhooks only | Header name to environment variable, for a service that wants a credential: `{ Authorization: GUARD_TOKEN }`. The value is read from the variable, never written in a file or a record. `enterplace serve` refuses to start, and a reload is rejected, while one is unset. |

What the built-in guardrails find:

| Type | Kinds |
|---|---|
| `secrets` | `private_key` (the whole PEM block), `aws_access_key`, `github_token`, `slack_token`, `enterplace_key`, `jwt`, `api_key` (`sk-...`) |
| `pii` | `email_address`, `phone_number`, `credit_card` (Luhn checked), `iban` (mod 97 checked), `israeli_id` (check digit), `us_ssn` |

Order: the built-in guardrails a rule names run first, then its webhooks in the order written. A `block` wins over a `mask`: a refused request is never changed. Once one guardrail blocks, no further webhook is called. A webhook sees the text after built-in masking.

The audit record of a rule with guardrails carries a `guardrails` list, one entry per guardrail and kind: `guardrail`, `detector`, `kind`, `action` (`block`, `mask`, `warn`, or `skipped`) and `count`. An empty list means they ran and found nothing. The matched text is never in the record, the refusal or Enterplace's log. When a guardrail masks, the provider gets the masked body; when nothing is masked, the body is forwarded byte for byte.

A change to `guardrails`, including a webhook's `url`, applies to the next request once the file is reloaded. See [Security model](security.html) for what guardrails do not catch.

## Budgets

`budget: { usd: 2000, per: month }` caps what the rule's callers spend in US dollars, from midnight UTC on the first of the month (`per: month`) or each day (`per: day`). It is counted per team for a `team` rule, per person for a `name` rule, and per person for an `any` rule. The count is all of that team's or person's spend in the period, under any rule, so a budget added mid-month starts from what was already spent.

A budget is checked when a request is admitted, not after it ends:

- The request reserves the most it could cost: one token per three bytes of its body, at the dearest prompt price the model has (input or cache write), plus its output tokens at the output price. The output tokens are the largest of `max_tokens`, `max_completion_tokens` and `max_output_tokens` (Responses), because a provider may read any one of them. A request that states none reserves the model's `max_output` from its price (built in for every model in the table), and is refused with `max_tokens_needed` (400) when the price has none. An embeddings request has no output tokens. A chat request with `n` (several answers) reserves its output tokens `n` times, because the provider writes and bills each answer; under a budget or a cache `n` must be a whole number from 1 to 16 (OpenAI allows 128, which would let one request cost 128 times its output limit), or the request is refused with `bad_limits`.
- A Responses request under a budget that names stored context (`previous_response_id`, `conversation` or `prompt`, when not null) makes the provider add earlier turns or a stored prompt the body does not hold, so the body says nothing of its real size. It is refused with `stored_context` (400), unless the model's price sets `max_context` (the most tokens of context the model reads): then it reserves that many input tokens instead of the body's estimate. Send the whole conversation in `input` instead, as Codex does (`store: false`, no `previous_response_id`; see [Codex](codex.html)). A request without a budget is not refused, and its cut-off estimate counts `max_context` when the price has it. Such a request is never answered from the cache: the conversation or stored prompt can change at the provider while the body stays the same.
- A request under a budget or a cache that names `model`, `messages`, `system`, `input`, `stream`, `n`, `previous_response_id`, `conversation`, `prompt` or one of the token limits twice, or gives a token limit that is not a whole number (`"1000000"`, `1.5`, `-1`), is refused with `bad_limits` (400): parsers differ on which copy wins, so the reservation could be of another request than the one the provider runs.
- It is admitted only if spent, plus what requests in flight have reserved, plus its own reservation, fits the budget. Otherwise it is refused with `budget_exceeded` (429, never retried by Claude Code), and the message says how much is spent of how much, what requests in flight hold, and when the budget starts again.
- When its answer ends, the reservation is replaced by its cost from the [usage record](audit.html#usage-records). An answer that reports no usage (an OpenAI chat stream sent without `stream_options.include_usage`, the OpenAI SDK's default, a whole answer without a `usage` field, or a stream that ended without its last event) is charged its whole reservation, and the usage record says `"usage": "not_reported"`. Send `stream_options: {"include_usage": true}` on OpenAI streams to be charged exactly what the provider reports. A reasoning model bills hidden reasoning tokens that never appear in the stream, so Enterplace cannot estimate such a stream from its text under a budget. Only for a request without a budget, where the charge feeds the Spend page and metrics but limits nothing, a stream the provider finished (`data: [DONE]`) without usage is charged an estimate from what it streamed: one output token per byte of streamed text plus one per event, and the prompt at one token per three bytes of the body; the usage record says `"usage": "estimated"`. Enterplace does not add `include_usage` to a request, because it never rewrites a request.
- A stream the caller closes before the event that carries its final usage (Anthropic's `message_stop`, OpenAI's usage chunk, Responses' `response.completed`, Gemini's last chunk), and a whole answer cut off half way, is charged the larger of what it reported so far and its reservation: the provider bills what it generated, not what the caller read. The usage record says `"usage": "partial"`. A request without a budget is charged the same estimate, so spend counted before a budget is added is not understated.
- `count_tokens` requests are free and reserve nothing.

Spend survives a restart: at start Enterplace sums the usage records of the current month from the audit log. A reload that changes a budget applies to the next request.

So a budget is passed only when a provider bills more than the request's reservation: a model writing more than its `max_tokens`, or a prompt that tokenizes to more than one token per three bytes. Requests in flight cannot pass it together: each one's reservation is counted before the next is admitted.

A key may carry a budget of its own as well (`budget:` on its entry in the keys file: [Keys](keys.html#expiry-and-budget-per-key)). A request then has to fit both, and one that would pass the key's is refused with `key_budget_exceeded`.

Every model a budgeted rule reaches must have a price (built in, or under `prices:`). For `models: ["*"]` that is every model every provider serves. A file that breaks this is refused by `enterplace check`.

## Rate limits

`rate: { rpm: 600 }` lets each person send at most 600 requests in any 60 seconds (a sliding minute, kept in memory, per Enterplace process). The next one is refused with `rate_limited` (429), with `Retry-After` set to the whole seconds until the oldest request leaves the minute and `x-should-retry: true`. A request answered from the cache does not count.

`rate: { tpm: 200000 }` limits tokens (prompt and answer) per sliding minute, counted where a budget is: per team for a team rule, per person for a name or `any` rule. `rpm` and `tpm` may be given together. Tokens are reserved as budgets reserve dollars: a request holds the most it could use (a token per three bytes of its body, plus its `max_tokens`, or the model's `max_output` under `prices:` when it sends none) until its answer ends, and then counts what the provider reported (prompt, answer and cache tokens), or what it held when no usage came back. A request that would pass the limit is refused with `rate_limited` and a `Retry-After`; one that could use more tokens than the limit allows in a whole minute is refused without one. Without `max_tokens` and without a `max_output` price, the tokens a request could use are unknown and it is refused with `max_tokens_needed`. Images, audio, moderations and rerank count their prompt only.

A key may carry `tpm:` of its own on its entry in the keys file, counted for that key alone and on top of its rule's.

## Models per key

A key may carry `models:` on its entry in the keys file:

```yaml
keys:
  - name: ci.release
    team: platform
    sha256: 3f1c...
    models: [gpt-4o-mini]
    tpm: 50000
```

The list narrows what the key's rule allows and never widens it: a request must be allowed by the rule and listed on the key. A model the rule allows and the key does not list is refused with `model_not_allowed`, naming the key and its list; `/v1/models` shows the key only what both allow. `models:` and `tpm:` are set with `enterplace key new --models gpt-4o-mini,o3 --tpm 200000`, with `"models"` and `"tpm"` on `POST /admin/keys`, or by editing the key's entry, and change without a restart. A refusal by either says so in its record: `key_models: true`, or `limit` with `of: "key"`.

## Aliases

`aliases:` at the top level names model names served by one or more deployments, with load balancing, cooldown and named fallbacks: see [Providers](providers.html#aliases-and-load-balancing). Rules name an alias as they name a model.

## Cache

`cache: { ttl_seconds: 300 }` keeps a whole answer for 300 seconds and serves it again for a request with the same provider, model, route (path and query) and request body, byte for byte, and the same `anthropic-beta` and `anthropic-version` headers. `count_tokens` is never cached. Only requests that are not streamed (`"stream": true` is never cached) and that do not carry `Cache-Control: no-store` are cached, and only answers with a 2xx status that ended whole are kept. The cache is in memory, 64 MiB across all rules, least recently used out first, and empties on restart.

A cache hit is still identified, decided and recorded: its decision record says `"cache": "hit"` and its usage record says cost 0. It never reaches the provider, and its answer carries `x-enterplace-cache: hit`. A request that could have been a hit and was not has `"cache": "miss"`. Two people whose requests are identical byte for byte get the same answer: give a rule a cache only where that is acceptable.

## Prices

Costs are in US dollars per million tokens. A model's price comes from, in order: the policy's `prices:`; Enterplace's own table (`gpt-4o-mini`, `gpt-4o`, `claude-sonnet-5-5`, `claude-haiku-5-5`, checked against each provider's price list on 13 November 2026); then a table of several thousand models generated by `scripts/prices.py` from LiteLLM's model price map (MIT licensed, attribution in `crates/enterplace-core/data/LICENSE-litellm-prices`), read on 13 November 2026 at a pinned commit. That table carries input, output, cache read and write, the 1 hour cache write, per image, `max_output`, `max_context` (the context window) and one long context tier where the map has them; a model listed there under a provider prefix only (`vertex_ai/...`) is also found by its bare name. Audio priced by the second is not in it. `enterplace prices <model> [--policy <file>]` prints the price used and where it came from, and each usage record says it in `price_source`. `prices:` sets or overrides a price by exact model name:

```yaml
prices:
  my-local-model: { input: 0, output: 0 }
  gpt-4o:
    input: 2.5
    output: 10
    cache_read: 1.25
    long_context: { above_prompt_tokens: 200000, price: { input: 5, output: 15 } }
```

| Key | Required | Meaning |
|---|---|---|
| `input`, `output` | yes | Price per million prompt tokens and per million output tokens. |
| `cache_read` | no | Per million prompt tokens read from the provider's cache. Default: `input`. |
| `cache_write` | no | Per million prompt tokens written to the cache. Default: `input`. |
| `cache_write_1h` | no | Per million tokens written to Anthropic's 1 hour cache. Default: `cache_write`. |
| `long_context` | no | `{ above_prompt_tokens: N, price: { ... } }`: a request whose whole prompt is longer than N tokens pays these prices for all of its tokens. |
| `max_context` | no | The most tokens of context the model reads in one request, above 0. A budget reserves this many input tokens for a Responses request that names stored context (`previous_response_id`, `conversation`, `prompt`); without it such a request is refused with `stored_context`. Enterplace trusts it as given: it must cover the largest stored context the model can read, its whole context window, or a request is charged more than it reserved and passes the budget by the difference (the usage record shows both, and Enterplace logs a line naming the model). Built in, from the LiteLLM table's context window, for the models that state one. |
| `per_image` | no | US dollars per image, for an image model billed by the image. An images request reserves `n` times it under a budget and is charged for each image its answer holds. An image or speech model priced by the token needs `max_output` instead: a budgeted request to it reserves `n` times `max_output`, and without either it is refused with `max_tokens_needed`. |
| `max_output` | no | The most output tokens the model writes in one answer, above 0. A budget reserves this many for a request that does not say `max_tokens`; without it such a request is refused with `max_tokens_needed`. Built in for every model of the tables that states it (16384 for `gpt-4o-mini` and `gpt-4o`, 64000 for `claude-sonnet-5-5` and `claude-haiku-5-5`). |

Every price is 0 or more. A model with no price still gets usage records, with the cost left unknown.

## Order on the request path

Each request the policy allows passes these steps in this order, and stops at the first that refuses it:

1. Identify the key, check the rule and the model, choose the provider, and translate a chat request for a provider with `accept_chat`.
2. The rule's guardrails, built-in first, then webhooks.
3. The cache: a hit is answered here.
4. The rate limit.
5. The budget: the request reserves the most it could cost.
6. The decision record is written. Nothing is sent before it is on file.
7. The request is sent, retried and passed to the fallback as the provider allows. An `attempts` record follows when more than one try was made, and a usage record when the answer ends.

Guardrails come before the cache on purpose. A cached answer is served only to a request that passes the guardrails in force now, so a guardrail added by a reload also covers answers cached before it. The cache key, the budget's estimate and the usage are of the body actually sent: masked, if a guardrail masked it, and translated, if it was translated. A request a guardrail blocks never reads the cache and never counts against a rate limit or a budget. The cost: a webhook guardrail is called on a cache hit too, and for a request the rate limit or the budget then refuses, so a caller over their limit still makes Enterplace call the guardrail vendor once per attempt.

The cache keeps the provider's own answer. A chat caller whose request was translated gets the hit translated, as the first answer was. Usage is read from the provider's answer before it is translated (a Bedrock stream after it is decoded), so a translated chat stream sent without `stream_options.include_usage` still has its tokens and cost recorded. When the request fell back to another provider, the usage record names the provider that answered.

## Not enforced, so refused

`tools` appears in Enterplace's designs but is not enforced by this version. A policy file that contains it is refused, so a file never promises what Enterplace does not do:

```text
enterplace.policy.yaml:20: "tools" is not enforced by this version of Enterplace. Remove the line: a policy file must not promise what Enterplace does not do yet.
```

## What `enterplace check` says

`enterplace check <policy> [--keys <file>]` prints every problem, one per line, each with file and line, then a count. One exception: a key Enterplace does not know (a typo such as `modles`) stops the check of that file there, because the rest cannot be read reliably; fix the names it lists and run it again to see any problem behind them. It exits with 0 when the files can be used and 1 when they cannot. The keys file is `enterplace.keys.yaml` beside the policy unless `--keys` names another; a missing keys file is fine (a new setup has a policy before its first key).

These are the messages, as this version prints them:

| Problem | Message |
|---|---|
| Misspelled key | `enterplace.policy.yaml:18: "modles" is not a key Enterplace knows. Did you mean "models"?` |
| Unknown key | `...: "colour" is not a key Enterplace knows. Remove it, or check the spelling.` |
| Key not enforced | `...: "tools" is not enforced by this version of Enterplace. Remove the line: ...` |
| Missing key | `...: "url" is missing here. Add it.` |
| Wrong type | `enterplace.policy.yaml:12: budget is integer 5. Write it as budget: { usd: 20, per: month }.` for a value that must be a map Enterplace knows (`budget`, `rate`, `cache`, `principals`, `audit`, `console`, a price); otherwise `...: models must be a list, such as [a, b], and it is integer 7.` |
| Key in the wrong place | `enterplace.policy.yaml:12: "retries" does not belong here. The keys here are name, principals, models, ... Move it to where it belongs, or remove it.` |
| Impossible expiry (keys file) | `enterplace.keys.yaml:4: expires 2026-11-31 is not a date: November 2026 has 30 days. Write a day that exists.` |
| Past expiry (`enterplace check` only) | `enterplace.keys.yaml:4: the key of "old.contractor" (key hash ca2561a2) has expired: expires 2026-11-01 has passed, so every request with it is refused. Remove the entry, or give it a later date.` `enterplace serve` and a reload still accept the file, because keys expire while Enterplace runs; `enterplace key new` and the admin API refuse to issue a key with a past date. |
| Broken YAML | `...: this is not valid YAML: <parser message>.` |
| Wrong version | `enterplace.policy.yaml:1: version is 2. This version of Enterplace reads version 1.` |
| No provider | `enterplace.policy.yaml:2: the file lists no provider, so no request could be forwarded. Add one under providers.` |
| Unknown kind | `enterplace.policy.yaml:4: kind is "palm". It must be openai (the chat completions API), anthropic (the messages API), azure (Azure OpenAI), bedrock (Amazon Bedrock, Anthropic models), gemini (Google's Gemini API) or vertex (Gemini on Google Cloud Vertex AI).` |
| Vertex URL | `enterplace.policy.yaml:5: a vertex provider's url ends in /publishers/google, for example https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google.` |
| File from version 0 (no `kind`, no `models`) | `old.yaml:3: provider "openai" must now say which API it speaks and which models it serves. Add these two lines under its name:` followed by the two lines to add |
| Empty `models` on a provider | `...: provider "openai" lists no models, so nothing would reach it. List the exact model names it serves.` |
| `"*"` on a provider | `...: a provider lists exact model names. "*" belongs in a rule, where it means every model.` |
| Empty model name | `...: provider "openai" lists an empty model name. List the exact model names it serves, or remove the empty one.` |
| No `kind` or no `models` | `enterplace.policy.yaml:3: provider "anthropic" must now say which API it speaks and which models it serves. Add this line under its name:` followed by only the missing line, with an example model of the provider's own kind |
| Model on two providers | `enterplace.policy.yaml:14: model "claude-sonnet-5-5" is listed by provider "anthropic" and by provider "local" at line 8. A model is served by one provider. Remove it from one of them.` |
| Two providers, one name | `...: two providers have the same name. Each provider needs its own name, because records name the provider that served each request.` |
| Bad URL | `...: the provider url must be a plain URL, with no login, query, fragment or spaces. Write it like https://api.openai.com, or with the vendor's path, like https://api.groq.com/openai/v1.` (and messages for a scheme other than http or https, and a port outside 1 to 65535) |
| No `url` or `key_env` | `enterplace.policy.yaml:3: provider "groq" has no url. Add the vendor's base URL, for example url: https://api.openai.com.` (a `bedrock` provider needs neither) |
| Azure | `...:12: api_version is a date, as Azure writes it: 2024-10-21, or 2025-04-01-preview for a preview version.`, `...: an azure provider needs deployments, ...`, `...:14: model "gpt-4o" has no entry in deployments, so Enterplace would not know what to call it at provider "azure". Add gpt-4o: <name> under deployments.` |
| Bedrock | `...: a bedrock provider needs region, ...`, `...: a bedrock provider needs model_ids, ...`, `...:26: a bedrock provider takes no key_env. Enterplace signs its requests with the AWS credentials it finds: the role of its pod, task or instance, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in its environment. Remove the line.` |
| Option of another kind | `...: region is for a provider of kind bedrock, and this one is of kind openai. Remove the line.` (and the same for `deployments`, `api_version`, `model_ids`; `accept_chat` is for `anthropic` and `bedrock`) |
| `retries` | `...:21: retries is at most 5. Each retry can wait as long as the provider's whole timeout, so more would leave a caller waiting for many minutes.` |
| `fallback` | `...:22: fallback names provider "bedrok", and there is none. The providers are: groq, azure, anthropic, bedrock.`, and refusals for a fallback that names itself, speaks the other API, or has no deployment or model ID for one of the models |
| Private URL | `enterplace.policy.yaml:5: the provider url points at this machine or a private network. If that is intended, for example a local model server, add allow_private: true to the provider.` |
| Bad `key_env` | `enterplace.policy.yaml:7: key_env is the name of an environment variable, for example OPENAI_API_KEY. The key itself never goes in this file.` |
| Bad name | `...: a provider name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters.` (and the same for a rule name) |
| Bad principals | `enterplace.policy.yaml:20: principals must be exactly one of { team: <team> }, { name: <person or workload> } or { any: true }.` |
| `"*"` with other models | `enterplace.policy.yaml:21: "*" already allows every model. List it alone, or list the models by name.` |
| Budget period | `enterplace.policy.yaml:17: per is "week". A budget starts again each day or each month (UTC): write per: day or per: month.` |
| Budget amount | `...: usd must be a number of US dollars above 0, for example budget: { usd: 2000, per: month }. To set no budget, remove the line.` |
| Budget on an unpriced model | `enterplace.policy.yaml:23: rule "everyone-else" has a budget in dollars, and model "my-model" has no price, so its spend could not be counted. Add its price in US dollars per million tokens under prices:, for example` followed by the lines to add |
| Rate | `enterplace.policy.yaml:18: rpm is the number of requests one person may send per minute, 1 to 1000000, for example rate: { rpm: 600 }. To set no limit, remove the line.` |
| Cache | `...: ttl_seconds is how long an answer is served again, 1 to 86400 seconds, for example cache: { ttl_seconds: 300 }. To cache nothing, remove the line.` |
| Bad price | `enterplace.policy.yaml:9: The price of model "o3" has a negative or non-numeric value. Give every price as US dollars per million tokens, 0 or more.` |
| Bad key hash | `enterplace.keys.yaml:4: sha256 must be 64 hex characters. Run enterplace key new to add a key instead of writing one by hand.` |
| Key listed twice | `...: this key is listed twice, the first time for "maya.cohen". Remove one of the two entries.` |
| Bad name or team in keys | `...: a name and a team use letters, digits, dots, dashes, underscores and @ only, at most 100 characters.` |
| Guardrail not defined | `enterplace.policy.yaml:31: rule "payments-team" names guardrail "no-secret", which is not defined under guardrails. Define it there, or check the spelling.` |
| Guardrail without an action | `enterplace.policy.yaml:20: guardrail "mask-pii" has no action. Add action: block, mask or warn.` |
| Webhook without `on_failure` | `...: guardrail "vendor" does not say what to do when the service fails. Add on_failure: fail_closed (refuse the request) or fail_open (forward it and record that the check did not run).` |
| Webhook over plain HTTP | `...: guardrail "vendor": the url must start with https://, or be http://localhost or http://127.0.0.1 for a service on this machine.` |
| Webhook with `action: mask` | `...: guardrail "vendor": a webhook guardrail does not take action: mask, because the service decides what to mask. ...` |
| Guardrail defined twice | `enterplace.policy.yaml: guardrail "pii" is defined twice. Give each guardrail its own name, because records name the guardrail that acted.` |

Warnings do not stop the file from loading. `enterplace check` prints one for a model a rule names that no provider serves, a provider model name with spaces at its start or end, a provider model name holding `*` (not a pattern there), and two provider model names that differ only in case or spaces.

The last line is always `<file> cannot be used: N problems above.` Two messages in the table drop the backticks the real output puts around `allow_private: true` and `enterplace key new`.

## Changes without a restart

Save the policy file or the keys file and Enterplace uses the new version within 2 seconds; `kill -HUP <pid>` makes it look at once. A change is checked with the same rules as `enterplace check`. One that passes is written to the audit log as a `config_loaded` record, then decides every request after it; one that fails is not used, and Enterplace keeps the version it has. Rules, guardrails, budgets, rate limits, caches, prices and keys all change this way, and a new budget or rate applies to the next request. Spend already counted and the cache are kept across a reload.

These need a restart, and a change to one of them is rejected with that reason: the audit log path; a provider's `name`, `kind`, `url`, `key_env`, `allow_private`, `region` or `api_version`; adding or removing a provider. Each audit record carries the SHA-256 of both files as they were loaded, so a record shows which version of the policy decided it.
