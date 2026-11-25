# Claude Code

Claude Code talks to Anthropic's messages API. Point it at Enterplace and give it an Enterplace key in place of a provider key. Each of its requests is then identified, decided and recorded.

## Policy

Claude Code uses a main model and a smaller one for background work. An `anthropic` provider must list both, and the person's rule must allow both:

```yaml
version: 1
providers:
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-5-5, claude-haiku-5-5]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [claude-sonnet-5-5, claude-haiku-5-5]
```

Keep the provider key in a variable of its own. Claude Code reads `ANTHROPIC_API_KEY` for its own key, which is the Enterplace key.

## Other providers

Claude Code reaches more than Anthropic's API through the same two lines:

- **Amazon Bedrock**: a provider of kind `bedrock` (see [Providers](providers.html)).
- **Claude on Vertex AI**: a provider of kind `vertex_anthropic`. Enterplace sends the body to `rawPredict` or `streamRawPredict`. Vertex AI names models without the date suffix (`claude-sonnet-4-6`), so map the name Claude Code sends with an alias.
- **GPT, Gemini or a local model**: a provider of kind `openai`, `azure`, `gemini` or `vertex` with `accept_messages: true`. Its requests are translated to chat completions and the answers, streamed or whole, tool calls included, back to Anthropic's format (see [Translation for Claude Code](providers.html#translation-for-claude-code)).

```yaml
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_PROVIDER_KEY
    models: [gpt-5, gpt-5-mini]
    accept_messages: true
```

```bash
export ANTHROPIC_MODEL=gpt-5
export ANTHROPIC_SMALL_FAST_MODEL=gpt-5-mini
```

Claude Code warns that it does not know the model and assumes a context window; see its model configuration docs to set one. A request field the chat API has no equivalent for is refused with `untranslatable`, naming the field. Tested with Claude Code 2.1.323 against a mock OpenAI chat server: a prompt, a Bash tool call and its result went through, streamed.

## Client settings

With single sign-on set up, a developer runs `enterplace login https://enterplace.example.com` once: it signs them in through the browser, saves a personal key named by their email, and prints the two lines below with their own key (see [Keys](keys.html#developers-get-their-own-key-enterplace-login)). Every request then carries their name. `enterplace logout` revokes it. Or an admin hands out a key:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_API_KEY=enterplace_...
export ANTHROPIC_MODEL=claude-sonnet-5-5
export ANTHROPIC_SMALL_FAST_MODEL=claude-haiku-5-5
claude
```

## What Enterplace does with its requests

- `POST /v1/messages` and `POST /v1/messages/count_tokens` are checked, recorded and forwarded as their original bytes to `anthropic` providers, including streamed answers, tool use and background calls. To `bedrock` and `vertex_anthropic` the body is rewritten as each takes it; to a provider with `accept_messages` it is translated.
- `anthropic-version`, `anthropic-beta` and every other `anthropic-*` and `x-claude-code-*` header pass unchanged, except to a provider with `accept_messages`, which gets no `anthropic-*` header.
- The `beta` query parameter Claude Code adds is forwarded when its value is `true` or `false`, once. Any other query parameter, another value, or the parameter twice is refused by name with `unknown_query`; the refusal never repeats the value.
- Its startup probe, `HEAD /api/hello`, is answered with 200 and not recorded: it reaches no provider. Any other method on `/api/hello` is refused with `unknown_route`, a decision ID and a record.

## Model picker

With `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1`, Claude Code asks Enterplace for its model list at startup (`GET /v1/models`). Enterplace answers with the models the messages route reaches (`anthropic`, `bedrock`, `vertex_anthropic`, and providers with `accept_messages: true`) that the person's rule allows, each described as `Allowed by Enterplace rule "<rule>"`. Each such request is recorded. Models on chat providers without `accept_messages` are left out, because Claude Code would offer them and every request would then be refused with `wrong_route`.

## Refusals in Claude Code

On the messages routes a refusal uses Anthropic's error shape, so Claude Code shows Enterplace's message:

```text
API Error: 403 Refused (model_not_allowed): team "interns" may not use model "claude-sonnet-5-5" under rule "everyone-else". This rule allows no models. Ask an Enterplace admin to change the policy if you need this one. Decision 01M7969SCWCX2P3AR3KSXZJ7VS.
```

Claude Code labels any 403 "Failed to authenticate"; the message after that label is Enterplace's. A model no provider serves is refused with 403 `unknown_model`, not 404, because Claude Code replaces the text of a 404 with its own and sends a 400 again several times; a 403 is shown as it is and sent once.

Every refusal sets `x-should-retry: false`, except the ones that may clear by themselves: `busy`, `rate_limited` (with `Retry-After` set to the seconds until the minute frees a slot) and the `upstream_*` codes, which set `x-should-retry: true`. Claude Code sends those again on its own. See [Refusal codes](refusals.html).

A guardrail refusal says where the finding is, in words and then as a JSON pointer into the request: `in message 3 (/messages/2/content/1/text)` is the third message of the conversation Claude Code sent, which may be an earlier turn, a file it read or a tool result. Remove the secret from that turn or file and send again; a new session starts without the earlier turns.

## Budgets and Claude Code

A budget reserves the most a request could cost before it is sent: its body at the input price plus its `max_tokens` at the output price. Claude Code asks for a large `max_tokens` on every request (32,000 or more, depending on the model), so on a priced model each request reserves far more than it usually spends (measured on 2026-11-13: $1.34 reserved per Claude Code request). The difference is given back when the answer ends and its real usage is charged, but while it is held, a small budget refuses requests that would have fitted (`budget_exceeded`, "could cost up to ..."). Two ways out:

- Lower what each request asks for: `export CLAUDE_CODE_MAX_OUTPUT_TOKENS=8000` before `claude`. Claude Code then sends that `max_tokens`, and each request reserves less.
- Size the budget for the reserve, not the average: a team that runs several sessions at once holds one reserve per request in flight.

When there is budget left, the refusal says so: "A request with a smaller output token limit ... could fit in what is left."

Codex and other clients of OpenAI's Responses API: see [Codex](codex.html).

