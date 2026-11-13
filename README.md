# Gantry

An AI gateway where governance comes first. Open source, Apache 2.0.

Status: early. One node. What works today: Claude Code and OpenAI-compatible clients send their requests through Gantry, and every request is identified by a Gantry key, checked against a policy file, written to a hash-chained audit log, and only then forwarded with the provider's key in place of the caller's. Providers that speak the OpenAI chat completions API (and its Responses and embeddings routes) or Anthropic's messages API are supported, including vendors whose base URL has a path and local servers without a key (Groq, Mistral, Together, Fireworks, DeepSeek, OpenRouter, Ollama, vLLM, LM Studio), Azure OpenAI, Claude on Amazon Bedrock, Claude on Vertex AI, and Gemini and Vertex AI with chat requests translated, with retries, a fallback per provider, and opt-in translation both ways: chat requests for Claude, and Claude Code's messages requests for GPT, Gemini or a local model (`accept_messages`). Model aliases spread one name over several deployments, with weights, cooldown and named fallbacks. Rules can run guardrails (built-in secret and personal data detectors, seven guardrail vendors such as OpenAI moderation and Lakera, and outside services by webhook) that block, mask or record what they find, on requests and on the model's answers (streamed answers when the rule sets `buffer_stream: true`). Each answer's tokens and cost are recorded, with prices built in for most models (generated from LiteLLM's MIT price map, see `gantry prices <model>`), and a rule can set a budget in dollars, requests and tokens per minute, and a cache. Images, audio transcription and speech, moderations and rerank routes are forwarded. Developers get their own expiring key with `gantry login`; admins stop traffic at once with `gantry kill`. `gantry import litellm` turns a LiteLLM proxy config into a policy (docs/migrate-litellm.md). Gantry can serve HTTPS itself (`--tls-cert`, `--tls-key`). An admin console is served at `/console`, with sign-in by admin key or through your identity provider (OpenID Connect) with admin and read-only roles. Keys can carry an expiry, a budget, a model list and a tokens-per-minute limit of their own. `GET /metrics` (Prometheus) is served on an address of its own when asked for. Codex CLI works through the Responses route (tested against a mock provider, see docs/codex.md).

What was tested against what: the OpenAI and Anthropic APIs were exercised live against mock servers and with the real Claude Code CLI and Codex CLI. Azure OpenAI, Amazon Bedrock, Gemini, Vertex AI and the OpenAI-compatible vendors above are configured from their public documentation and tested against local mocks only, never against the real services yet.

Build and CI: a CI workflow is defined in `.github/workflows/ci.yml` and runs `scripts/ci.sh` (format, clippy with warnings as errors, every test, the release build, every policy example through `gantry check`, the bench gate, the docs build). Nothing is committed yet, so it has not run on a hosted service: `scripts/ci.sh` passes on a developer machine. The container image runs as user 65532 and passes `scripts/smoke_image.py`; `scripts/release.sh image` prints its size for each build and writes it to `dist/image-size.txt`, from which the docs site and website take it.

## Run

Write `gantry.policy.yaml`:

```yaml
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
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini, claude-sonnet-5-5, claude-haiku-5-5]
    budget: { usd: 2000, per: month }
    rate: { rpm: 600 }
  - name: everyone-else
    principals: { any: true }
    models: []
```

The provider keys go in variables of their own, named by `key_env`. Avoid `ANTHROPIC_API_KEY` there: Claude Code reads that variable for its own key, which is a Gantry key.

Each provider says which API it speaks (`kind: openai` for chat completions, `kind: anthropic` for messages, `kind: azure` for Azure OpenAI, `kind: bedrock` for Claude on Amazon Bedrock, `kind: gemini` for Google's Gemini API, `kind: vertex` for Gemini on Vertex AI) and lists the exact models it serves. A model is served by one provider. A request goes to the provider that lists its model, and only on that provider's route: `/v1/chat/completions` for `openai`, `azure`, `gemini` and `vertex` (the last two translated), `/v1/responses` and `/v1/embeddings` for `openai`, `/v1/messages` and `/v1/messages/count_tokens` for `anthropic`, `/v1/messages` for `bedrock`. A provider with `accept_chat: true` (`anthropic` or `bedrock`) also takes chat requests, translated. `retries: N` and `fallback: <provider>` try again, before any byte of the answer reaches the caller, after a connection failure, a timeout, a 429 or a 5xx. A `url` may carry the vendor's path, such as `https://api.groq.com/openai/v1`: the route after `/v1` is added to it. See docs/providers.md for Azure's `deployments` and `api_version`, Bedrock's `region`, `model_ids` and AWS variables, and every example.

Rules are read in order and the first one that names the caller decides. `principals` is one of `{ team: ... }`, `{ name: ... }` or `{ any: true }`. `models` lists exact names, or `["*"]` for every model. A provider on this machine or a private network, such as a local model server, needs `allow_private: true` beside its `url`; an `openai` one may then leave out `key_env`, and gets no key.

`budget` caps a team's spend (a person's, for a `name` or `any` rule) per `day` or `month`, UTC. Each request reserves the most it could cost before it is sent (its largest token limit, or the model's `max_output` when it states none) and is refused with `budget_exceeded` if that would pass the budget; when its answer ends, the reservation becomes its real cost, and a stream the caller closes before its final usage is charged at least its reservation. `rate: { rpm: N }` limits each person to N requests a minute, and `rate: { tpm: N }` tokens a minute (`rate_limited`, with `Retry-After`). `cache: { ttl_seconds: N }` serves the same answer again for the same request body on the same route without calling the provider. Prices of most models are built in (`gantry prices <model>` shows the one used and where it came from); `prices:` adds or overrides them. See [docs/policy.md](docs/policy.md).

```bash
cargo build --release
```

The binary is `target/release/gantry`. The commands below assume it is on your `PATH`.

```bash
gantry check gantry.policy.yaml
```

```bash
gantry key new noa.bar --team platform --admin
gantry key new maya.cohen --team payments
```

The first command makes the first admin, who may sign in to the console and issue keys from there. The key is printed once, with the lines that point Claude Code and the OpenAI SDKs at Gantry, ready to send through your secret manager (`--url` sets the gateway's address, `--quiet` prints the key alone). `--expires 2026-12-31` refuses the key from that UTC day on (`key_expired`), and `--budget 20/month` caps what this one key may spend (`key_budget_exceeded`), on top of its rule's budget; both reload without a restart. `gantry key list` shows every key's name, team, hash prefix, admin flag, expiry and budget, never a key. Only its SHA-256 goes into `gantry.keys.yaml`, which is created readable by its owner only. To remove a key, delete its entry and save the file: Gantry stops accepting it within 2 seconds. `gantry key new` adds its entry to the end of the file and never rewrites what is there, so a key someone removed by hand stays removed. An editor that saves the file at the same moment from an older copy can drop the new entry; `key new` shows a key only after finding it in the file, and otherwise asks you to run it again.

```bash
OPENAI_PROVIDER_KEY=... ANTHROPIC_PROVIDER_KEY=... gantry serve gantry.policy.yaml
```

```bash
curl http://127.0.0.1:8080/v1/chat/completions -H "Authorization: Bearer $GANTRY_KEY" -H "Content-Type: application/json" -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello."}]}'
```

Every response carries `X-Gantry-Decision`. A refusal repeats the ID in its message, with a stable `code`. Each request leaves one record in `gantry-audit.jsonl`, and each forwarded request a second, its usage record (tokens and cost in US dollars), when its answer ends:

```bash
gantry audit verify gantry-audit.jsonl
```

`audit verify` proves the chain is unbroken from the first record to the last one in the file, and counts request, configuration, admin and usage records apart. It cannot see records removed from the end, so it prints the last hash. Keep that hash somewhere Gantry's host cannot write (a ticket, a chat message, another machine), and check it later:

```bash
gantry audit verify gantry-audit.jsonl --expect-last 3f9a...
```

This passes only if a record with that hash is still in the chain and nothing before it was changed, and prints that record's number. A failure says which of two things happened: the hash is not in this file (records up to it were removed, or this is another log), or the chain is broken before it (a record was changed).

A write that failed part way (a full disk) can leave the last line cut short; `gantry serve` then refuses to start and names the command. `gantry audit repair gantry-audit.jsonl` shows that line, and with `--yes` removes only it and records the repair in the chain ([Audit log](docs/audit.md#a-last-line-cut-short)).

With a policy, Gantry forwards the query parameters a route allows, with the values each takes (`beta=true` or `beta=false` on the messages routes, `limit` from 1 to 1000 on `/v1/models`), and refuses any other parameter or value by name. It drops every request header whose name contains authorization, key, token, secret, organization or project, except `idempotency-key`, every `x-amz*` header, and any header that carries the caller's Gantry key in its name or value (a hand-made key under 16 characters only where it stands as a word of its own). `anthropic-*` and `x-claude-code-*` headers pass unchanged.

Known limits of this version: one caller's requests in flight may hold at most 64 MiB of request bodies; the decision record says what Gantry decided, not how the provider answered (a usage record with the status, tokens and cost follows when the answer ends, and an `attempts` record when a request was tried more than once); a request hyper itself rejects as malformed gets a bare 400 with no decision ID; Gantry serves plain HTTP unless started with `--tls-cert` and `--tls-key`, so use those or put TLS in front of it before it leaves one machine.

`gantry serve --unchecked` forwards without identity, policy or audit, on a loopback address only. It exists for benchmarks. `GANTRY_ADDR` and `GANTRY_UPSTREAM` configure it.

## Changing the policy and keys

Save the policy file or the keys file and Gantry uses the new version within 2 seconds, without a restart. `kill -HUP <pid>` makes it check at once. Gantry compares the SHA-256 of both files once a second, so an editor that saves by renaming a new file into place and a symlink switched to another file are both noticed.

A change is checked with the same rules as `gantry check`. One that passes is written to the audit log as a `config_loaded` record first, then used for every request decided after it: the policy and the keys switch together, and each request record carries the `policy_sha256` and `keys_sha256` of the version that decided it. A request decided before the switch finishes under the decision it got, so a revoked key stops working within 2 seconds without cutting anyone's answer in flight, its own stream included.

A change that fails is not used. Gantry keeps deciding with the version it has, prints every problem to stderr with its file and line, writes one `config_rejected` record per distinct pair of files (not one per second), and uses the next save that passes. For example:

```
/etc/gantry/gantry.policy.yaml:12: "modles" is not a key Gantry knows. Did you mean "models"?
gantry: the change to /etc/gantry/gantry.policy.yaml or /etc/gantry/gantry.keys.yaml is not used: 1 problem above. Gantry keeps deciding with the version it has (policy 5d41402a, keys 7c211433) and uses the next save that passes `gantry check`.
```

A missing policy or keys file is a failed change too. These settings need a restart, and a change to one of them is rejected with that reason: the audit log path; a provider's `name`, `kind`, `url`, `key_env`, `allow_private`, `region` or `api_version`; adding or removing a provider. A provider's `models`, `deployments`, `model_ids`, `retries`, `fallback` and `accept_chat`, every rule and every key may change without one. Rotating a provider key means changing its environment variable, which needs a restart.

Each `config_loaded` record holds the trigger (`start`, `file_change` or `signal`), the hashes before and after, the whole policy text (it holds no secrets) and the keys added and removed, each by name, team and the first 8 characters of its hash. At start, "before" is the last version the log recorded, so a change made while Gantry was stopped shows. Who edited a file is not known to Gantry: keep the files in version control for that.

`GET /healthz` answers 200, or 503 when the audit log cannot be written, as before. Its body names the hashes in use and those of a rejected version on disk:

```json
{"status":"ok","policy_sha256":"5d41...","keys_sha256":"7c21...","rejected":null}
```

`gantry check` also warns, without failing, when a rule names a model no provider serves.

## Admin API for keys

Keys can be issued and revoked over HTTP while Gantry runs, on the same address. An admin key is one made with `gantry key new <name> --team <team> --admin`, which writes `admin: true` in its entry:

```yaml
keys:
  - name: ops.admin
    team: platform
    sha256: 9b74...
    admin: true
```

Only a key marked this way may call the routes below, wherever Gantry listens; any other key gets 403 `not_admin`, no key 401 `no_key`. Every call, allowed or refused, is a record in the audit log (`"event": "admin"`, the action, who called, the key concerned), written before anything is done.

| Route | Does |
|---|---|
| `POST /admin/keys` with `{"name": "maya.cohen", "team": "payments"}` | Issues a key. Optional: `"expires": "2026-12-31"` and `"budget": {"usd": 20, "per": "month"}`. The answer (201) holds the key once; only its hash goes into the keys file, appended to the end exactly as `gantry key new` does. The key works as soon as the answer arrives. |
| `GET /admin/keys` | Lists the keys in use: name, team, first 8 hex characters of the hash, whether it is an admin key, its expiry and its budget. Never a key. |
| `DELETE /admin/keys/<first 8 hex of the hash>` | Removes that entry from the keys file, only if nobody changed the file meanwhile, and stops the key at once. 404 `no_such_key` if no entry has that hash. |

```bash
curl -X POST http://127.0.0.1:8080/admin/keys -H "Authorization: Bearer $GANTRY_ADMIN_KEY" -H "Content-Type: application/json" -d '{"name":"maya.cohen","team":"payments"}'
curl -X DELETE http://127.0.0.1:8080/admin/keys/1a2b3c4d -H "Authorization: Bearer $GANTRY_ADMIN_KEY"
```

The keys file stays the one source of truth: an issued or revoked key is a change to the file, and is recorded as a `config_loaded` record like any other. If the files on disk fail the check for another reason at that moment, the answer says the change is not in effect yet and lists the problems.

## Guardrails

A rule can name guardrails that check the text of each request it allows, after the policy decision and before the record is written and the request sent, and, with `on: [answer]`, the model's answer before it reaches the caller (docs/guardrails.md). They read chat, messages, Responses and embeddings requests (docs/policy.md lists what each route reads), and may be built in (`secrets`, `pii`), a vendor (docs/guardrails.md) or a webhook.

```yaml
guardrails:
  - name: no-secrets
    type: secrets            # AWS, GitHub, Slack, JWT, sk- and Gantry keys, PEM private keys
    action: block            # refuse with guardrail_blocked (403)
  - name: mask-pii
    type: pii                # email, phone, card, IBAN, Israeli ID, US SSN
    action: mask             # forward with [MASKED email_address] in place of each finding
  - name: vendor
    type: webhook            # an outside guardrail service: docs/guardrail-webhook.md
    url: http://127.0.0.1:9100/check
    timeout_ms: 800
    on_failure: fail_closed
    headers_env: { Authorization: GUARD_TOKEN }  # header to send, from this variable; never in a file or a record
rules:
  - name: everyone
    principals: { any: true }
    models: ["*"]
    guardrails: [no-secrets, mask-pii, vendor]
```

Guardrails run before the cache, the rate limit and the budget, so a cached answer is only served to a request that passes them, and the cache key is of the body sent (masked, if a guardrail masked it). `warn` records findings and forwards the request unchanged. The audit record lists each guardrail, kind, action and count, never the matched text. A change to guardrails applies to the next request after the file is reloaded. What they do not catch is in docs/security.md.

## Admin console

`gantry serve` serves the console at `/console`. Sign in with an admin key, or through your identity provider (OpenID Connect, `console.sso` in the policy), with admin and read-only roles from a claim: docs/security.md. It shows the audit log (with each record's guardrail findings), the people and keys, the policy, and spend against each budget, and it issues and revokes keys, including admin keys. Every sign-in, sign-out, issue and revoke is an `"event": "admin"` record in the same chain, with who did it, written before it is done.

## Claude Code

Point Claude Code at Gantry and give it a Gantry key in place of a provider key:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_API_KEY=gantry_...
export ANTHROPIC_MODEL=claude-sonnet-5-5
export ANTHROPIC_SMALL_FAST_MODEL=claude-haiku-5-5
claude
```

Claude Code uses a second, smaller model for background work, so the policy must allow both models it is set to use, and a provider that takes messages requests must list both: `anthropic`, `bedrock`, `vertex_anthropic`, or a chat provider with `accept_messages: true` (docs/claude-code.md). Each of its requests then has a record in the audit log. A refusal shows in Claude Code with its reason and decision ID, for example `API Error: 403 Refused (model_not_allowed): ... Decision 01...`. Claude Code calls any 403 "Failed to authenticate"; the message after it is Gantry's.

Gantry forwards the `anthropic-version` and `anthropic-beta` headers as they came, and the `beta` query parameter Claude Code adds (`true` or `false`). Any other query parameter or value is refused by name.

With `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1`, Claude Code asks Gantry for its model list at startup, and its `/model` picker shows the models on the messages API that the person's rule allows. Each such request is recorded. Claude Code's startup probe, `HEAD /api/hello`, is answered and not recorded: it reaches no provider. Any other method there, and any method but `GET` on `/healthz`, is refused with `unknown_route` and recorded.

## Codex

Codex CLI sends OpenAI Responses requests. Give it a provider in `~/.codex/config.toml` with `base_url = "http://127.0.0.1:8080/v1"`, `env_key = "GANTRY_KEY"` and `wire_api = "responses"`, put a Gantry key in `GANTRY_KEY`, and allow its model on an `openai` provider. Set `stream_max_retries = 0` there, or Codex sends a refused request six times. Full settings and what refusals look like: docs/codex.md.

## Container

```bash
scripts/release.sh image
```

The image holds one static binary (9.1 MB as measured for gantry 0.0.1, src d88a5ce58bfa, on 2026-11-13; `scripts/release.sh image` prints the size of each build), runs as a user without privileges, and reads the policy and keys files from `/etc/gantry`. The audit log goes on a volume: set `audit: { path: /var/lib/gantry/gantry-audit.jsonl }` in the policy file. The run command is at the top of the `Dockerfile`.

## Metrics and log shipping

`gantry serve gantry.policy.yaml --metrics 127.0.0.1:9464` serves `GET /metrics` in the Prometheus text format on that address only: requests by route, verdict, refusal code and provider; provider answers by status; latency of providers and of Gantry itself; audit log write time and queue depth; dollars charged by team and model. It is off unless asked for, and takes no key, so keep it on loopback or a network only your scraper reaches. To ship the audit log to Loki, Elasticsearch, Splunk or Datadog, tail the JSONL file: docs/observability.md has Vector, Fluent Bit and OpenTelemetry Collector examples.

## Measure

```bash
cargo run --release -p gantry-bench -- --rps 1000 --secs 10 --max-p99-overhead-us 1000
```

This runs a mock model server and the gateway in one process, sends the same load to each, and prints what the gateway adds as the client sees it, plus the time the gateway reports for identifying, deciding and recording. With the policy on (1,000 keys, a `secrets` guardrail on every rule) it also checks that the audit log holds exactly one decision record and one usage record per request. Add `--stream` for streamed responses and `--messages` for Claude Code's route, `/v1/messages`. Writing the audit record before forwarding costs about 70 to 100 microseconds per request on a laptop, most of it waiting for the writer thread to wake. At 5,000 requests a second on one laptop the 1,000 microsecond gate does not hold on every run, so CI gates at 1,000, after a warm-up, passing if one of three attempts passes (docs/operations.md). The numbers compare builds on one machine. They are not a published benchmark.

## Develop

```bash
scripts/ci.sh
```

The same checks CI runs. `scripts/ci.sh --no-bench` skips the bench gate on a busy machine.

Conventions are in `AGENTS.md`.
