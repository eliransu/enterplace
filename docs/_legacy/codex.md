# Codex

Codex CLI talks to OpenAI's Responses API (`POST /v1/responses`). Point it at Enterplace through a model provider of its own and give it a Enterplace key in place of a provider key. Each of its requests is then identified, decided, checked by the rule's guardrails, recorded and only then forwarded.

Tested against: Codex CLI 0.166.0 (`codex exec`) through Enterplace to a mock of the Responses API on this machine, on 2026-11-13: answers, token counts, records, and the refusals shown below. Not yet run against OpenAI itself.

## Policy

The models Codex asks for must be on a provider of `kind: openai` (OpenAI itself, or a vendor that serves the Responses API), and the person's rule must allow them. Azure, Gemini, Vertex, Anthropic and Bedrock providers do not take `/v1/responses`: a request for one of their models is refused with `wrong_route`.

```yaml
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com/v1
    key_env: OPENAI_PROVIDER_KEY
    models: [gpt-5-codex, gpt-4o-mini]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-5-codex, gpt-4o-mini]
```

Keep the provider key in a variable of its own (here `OPENAI_PROVIDER_KEY`), so the Enterplace key a developer holds and the provider key Enterplace holds never share a name.

## Client settings

Add a provider to Codex's configuration file, `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`), and make it the default:

```toml
model = "gpt-5-codex"
model_provider = "enterplace"

[model_providers.enterplace]
name = "Enterplace"
base_url = "http://127.0.0.1:8080/v1"   # Enterplace's address, with /v1
env_key = "ENTERPLACE_KEY"                  # the variable that holds the Enterplace key
wire_api = "responses"
stream_max_retries = 0                  # see "Retries" below
```

Then give it the key and run it:

```bash
export ENTERPLACE_KEY=enterplace_...
codex
```

`enterplace login https://enterplace.example.com` gets a personal key through single sign-on and prints `export ENTERPLACE_KEY=...` with it (see [Keys](keys.html#developers-get-their-own-key-enterplace-login)); `enterplace logout` revokes it. Otherwise `enterplace key new` prints the key; pass `--quiet` to print the key alone. The provider ID must not be one Codex reserves (`openai`, `ollama`, `lmstudio` and a few more), so the example calls it `enterplace`. Codex sends the key as `Authorization: Bearer`, which is how Enterplace reads it.

For a model Codex has no built-in description of, it prints `warning: Model metadata for "<model>" not found. Defaulting to fallback metadata` and carries on. The warning is Codex's own and does not come from Enterplace.

## What Enterplace does with its requests

- `POST /v1/responses` is checked, recorded and forwarded as its original bytes to the Responses endpoint of the `openai` provider that lists the model (see [Providers](providers.html)), streamed answers included. The usage record holds the tokens and cost of the answer.
- The guardrails read the Responses `instructions` and every `input` text (a string, or the `input_text` parts of input messages).
- Budgets reserve the most a request could cost before it is sent, from `max_output_tokens` or the model's `max_output` price entry. See [Policy file](policy.html).
- Codex sends `store: false` and the whole conversation in `input` on every turn, with no `previous_response_id`, `conversation` or `prompt` (measured with Codex CLI 0.166.0 against a capture on this machine, 2026-11-13). So its requests work under a budget, and each one's reservation counts its whole history. A client that does send those fields is refused under a budget with `stored_context`, unless the model's price sets `max_context`, because the provider would add stored context the reservation never saw. The limit of this: on a long session each request carries, and reserves, its whole conversation.
- Other Responses routes (`GET /v1/responses/{id}`, `DELETE`, cancel) are not built and are refused with `unknown_route`. Codex does not need them for a session.

## Refusals in Codex

On `/v1/responses` a refusal uses OpenAI's error shape, so Codex prints Enterplace's message after its own prefix:

```text
ERROR: unexpected status 403 Forbidden: Refused (model_not_allowed): team "t" may not use model "gpt-4o" under rule "everyone". Allowed: gpt-4o-mini. Ask a Enterplace admin to change the policy if you need this one. Decision 01M79K3AKCRTY593P82PZPG1GE., url: http://127.0.0.1:20770/v1/responses
```

```text
ERROR: unexpected status 401 Unauthorized: Refused (unknown_key): Enterplace does not know this key. It was never issued or it has been removed. A key just issued works within 2 seconds. Ask a Enterplace admin. Decision 01M79K3Q28V5EXP60V1YSSA595., url: http://127.0.0.1:20770/v1/responses
```

Quote the decision ID to an admin: it finds the record. Every code is in [Refusal codes](refusals.html).

## Retries

Codex retries a failed streamed request up to `stream_max_retries` times (5 by default), and prints `Reconnecting... 1/5` for each. It does this for a refusal too, although Enterplace sends `x-should-retry: false`: with the default, one refused prompt makes six identical refusals, six records and, on a rule with a webhook guardrail, six calls to the guardrail service. With `stream_max_retries = 0` in the provider's table, as above, a refusal is sent once and recorded once (measured with Codex CLI 0.166.0). `request_max_retries` alone does not change this.

The cost of 0: a stream cut by the network is not resumed, and the person runs the prompt again. Enterplace's own retries to the provider (`retries:` on the provider) still apply on the server side.

## Not built yet (planned)

- A Cursor guide: Cursor has not been run through Enterplace.

Sources, read on 2026-11-13: https://developers.openai.com/codex/config-advanced (now served at https://learn.chatgpt.com/docs/config-file/config-advanced) and https://learn.chatgpt.com/docs/config-file/config-reference.
