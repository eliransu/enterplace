# Coding agents

Cursor, Continue, Cline, Aider and OpenCode can each send their model requests to Gantry instead of to a provider. Give the tool Gantry's address and a Gantry key in place of a provider key. Each request is then identified, decided, recorded and only then forwarded.

Of the five, only OpenCode has been run through Gantry. The others are described from their own documentation; the last section says which is which. For Claude Code and Codex, see [Claude Code](claude-code.html) and [Codex](codex.html).

## What every tool needs

- **Address.** Gantry serves OpenAI's chat completions at `POST /v1/chat/completions` and Anthropic's messages at `POST /v1/messages`. A tool that speaks OpenAI's API takes Gantry's address with `/v1` (`http://127.0.0.1:8080/v1`) and adds `/chat/completions` itself.
- **Key.** Gantry reads the key from `Authorization: Bearer gantry_...` or from `x-api-key: gantry_...`. Either works; both at once must hold the same value, or the request is refused with `ambiguous_key`. Put the Gantry key wherever the tool asks for an API key. Never give the tool a provider key: a key that starts with `sk-` is refused with `unknown_key` and a hint.
- **Policy.** The models the tool asks for must be on a provider and allowed by the person's rule. A tool that only speaks chat completions can use Claude models only if the admin sets `accept_chat: true` on the `anthropic` provider (see [Providers](providers.html#translation-for-chat-clients)); without it, those requests are refused with `wrong_route`.
- **Refusals.** On `/v1/chat/completions` a refusal uses OpenAI's error shape, on `/v1/messages` Anthropic's. In both, the message starts with `Refused (<code>):` and ends with `Decision <id>.`, because most tools show only the message. See [Refusal codes](refusals.html).

## Cursor

Cursor's own servers build the final prompt and send the request, also when you give it your own key. Its documentation says so for API keys, and Cursor staff confirm it for the base URL override on Cursor's forum. So a Gantry on `127.0.0.1` or on a private network cannot be reached from Cursor: Gantry must have a public HTTPS address (TLS in front of it, see [Operations](operations.html#tls)), and every Gantry key travels through Cursor's servers.

- **Base URL:** Cursor Settings, Models, the OpenAI API key section, "Override OpenAI Base URL". Enter Gantry's public address with `/v1`.
- **Key:** the "OpenAI API Key" field in the same section. Enter the Gantry key.
- **Route:** `POST /v1/chat/completions`.

```text
OpenAI API Key:            gantry_...
Override OpenAI Base URL:  https://gantry.example.com/v1
Model name:                the model as the policy names it, for example gpt-4o-mini
```

Caveats:

- Tab completion always uses Cursor's own models and never reaches Gantry. Only chat and agent requests do.
- With the override on, every OpenAI-family request goes to Gantry, including models picked from Cursor's built-in list (confirmed by Cursor staff, 2026-08-21). Those are refused unless the policy allows them. There is no per-model base URL yet.
- Cursor's documentation shows no base URL override for its Anthropic key.
- How Cursor shows a refusal is not documented. Not tested.

## Continue

Continue reads models from its `config.yaml` (Continue keeps its data in `~/.continue`). Use the `openai` provider with `apiBase`.

- **Base URL:** `apiBase` on the model.
- **Key:** `apiKey` on the model, best as a secret: `${{ secrets.GANTRY_KEY }}`.
- **Route:** `POST /v1/chat/completions`.

```yaml
name: Gantry
version: 0.0.1
schema: v1
models:
  - name: gpt-4o-mini via Gantry
    provider: openai
    model: gpt-4o-mini
    apiBase: http://127.0.0.1:8080/v1
    apiKey: ${{ secrets.GANTRY_KEY }}
    roles: [chat, edit, apply]
```

Put the key in `~/.continue/.env` (or in `.env` or `.continue/.env` in the workspace):

```bash
GANTRY_KEY=gantry_...
```

Caveats:

- Continue's VS Code and JetBrains extensions do not read shell environment variables, so `export GANTRY_KEY=...` is not enough there: use a `.env` file and restart the IDE. Only the Continue CLI reads the process environment.
- Without `apiBase`, the `openai` provider sends the key to OpenAI.
- Continue's documentation for its `anthropic` provider shows no `apiBase`, so this guide uses the `openai` provider only.
- The example leaves out the `autocomplete` role: Gantry serves chat completions, and autocomplete through Gantry was not tried.
- How Continue shows a refusal is not documented. Not tested.

## Cline

Cline is configured in its settings panel in VS Code, not in a file. It can use Gantry through either API.

OpenAI's API:

- **API Provider:** OpenAI Compatible.
- **Base URL:** Gantry's address with `/v1`, for example `http://127.0.0.1:8080/v1`.
- **API Key:** the Gantry key.
- **Model:** the model as the policy names it.
- **Route:** `POST /v1/chat/completions`.

Anthropic's API:

- **API Provider:** Anthropic.
- **API Key:** the Gantry key.
- **Use custom base URL:** checked, with Gantry's address (`http://127.0.0.1:8080`).
- **Route:** `POST /v1/messages`, where refusals use Anthropic's error shape.

Caveats:

- Cline's documentation says the OpenAI Compatible base URL is the provider's endpoint and gives no example, so whether Cline wants `/v1` at the end is from the OpenAI convention, not from Cline. A 404 `unknown_route` from Gantry means the path is wrong.
- The Anthropic page does not name the URL field beside "Use custom base URL".
- Cline's troubleshooting lists "Invalid API Key" and "Model Not Found" errors; whether it shows Gantry's message text is not documented. Not tested.

## Aider

Aider reaches an OpenAI-compatible server through two environment variables and a model name with the `openai/` prefix.

- **Base URL:** `OPENAI_API_BASE`.
- **Key:** `OPENAI_API_KEY`.
- **Route:** `POST /v1/chat/completions`.

```bash
export OPENAI_API_BASE=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=gantry_...
aider --model openai/gpt-4o-mini
```

The `openai/` prefix tells Aider which API to use; the model name sent to Gantry is the part after it, which the policy must allow.

Caveats:

- Aider warns about models it has no information on. The warning is Aider's own.
- Aider's Anthropic page documents only `ANTHROPIC_API_KEY`, no base URL, so this guide uses the OpenAI route.
- How Aider shows a refusal is not documented. Not tested.

## OpenCode

OpenCode takes a provider of its own in its configuration file. Point `OPENCODE_CONFIG` at the file to use one outside the default location.

- **Base URL:** `provider.<id>.options.baseURL`.
- **Key:** `provider.<id>.options.apiKey`, read from a variable with `{env:GANTRY_KEY}`.
- **Route:** `POST /v1/chat/completions` with the `@ai-sdk/openai-compatible` package. OpenCode sends the key as `Authorization: Bearer`.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "gantry": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Gantry",
      "options": {
        "baseURL": "http://127.0.0.1:8080/v1",
        "apiKey": "{env:GANTRY_KEY}"
      },
      "models": {
        "gpt-4o-mini": { "name": "gpt-4o-mini" }
      }
    }
  }
}
```

```bash
export GANTRY_KEY=gantry_...
opencode run -m gantry/gpt-4o-mini "Say hello."
```

A refusal is shown with Gantry's message:

```text
> build · gpt-4o
Error: Refused (model_not_allowed): team "payments" may not use model "gpt-4o" under rule "payments-team". Allowed: gpt-4o-mini. Ask a Gantry admin to change the policy if you need this one. Decision 01M79QS3FKFHJAQSYW8BMX3E5F.
```

```text
Error: Refused (unknown_key): Gantry does not know this key. It was never issued or it has been removed. A key just issued works within 2 seconds. Ask a Gantry admin. Decision 01M79QS9S2XNB6ZDE3MT1TTN59.
```

Caveats:

- The example uses the configuration format of OpenCode V1, which OpenCode 1.19.5 reads. OpenCode's current documentation describes a V2 format (`providers`, `package`, `settings.baseURL`). OpenCode 1.19.5 drops those keys without a warning (`opencode debug config` no longer shows them), and the provider is missing. Run `opencode debug config` to see which format your version kept.
- Each prompt makes two requests: one for the session title and one for the answer. Both are recorded, so a refused prompt leaves two refusals in the audit log.
- OpenCode did not send a request refused with 403 again, and marked the error not retryable. Whether it retries a 429 refusal such as `budget_exceeded` was not tried.
- To use the Anthropic route, OpenCode's V1 documentation sets `provider.anthropic.options.baseURL`, with `/v1` (`http://127.0.0.1:8080/v1`), and the key in `options.apiKey`. Not tested.

## Tested

- Cursor: from docs only.
- Continue: from docs only.
- Cline: from docs only.
- Aider: from docs only.
- OpenCode: tested live. OpenCode 1.19.5 (`opencode run`) through Gantry to a mock of the chat completions API on this machine, on 2026-11-13: an answer, a `model_not_allowed` refusal and an `unknown_key` refusal, each recorded. Not run against a real provider, and the Anthropic route was not tried.

## Sources

Read on 2026-11-13:

- https://cursor.com/docs
- https://cursor.com/llms.txt
- https://cursor.com/help/models-and-usage/api-keys
- https://forum.cursor.com/t/cursor-managed-models-are-routed-through-override-openai-base-url/169088
- https://forum.cursor.com/t/how-to-use-a-custom-openai-compatible-api-in-cursor-setup-limits-and-tips/171497
- https://docs.continue.dev/customize/model-providers/top-level/openai
- https://docs.continue.dev/customize/model-providers/top-level/anthropic
- https://docs.continue.dev/reference
- https://docs.continue.dev/faqs
- https://docs.cline.bot/provider-config/openai-compatible
- https://docs.cline.bot/provider-config/anthropic
- https://aider.chat/docs/llms/openai-compat.html
- https://aider.chat/docs/llms/anthropic.html
- https://opencode.ai/docs/providers/
- https://opencode.ai/docs/config/
- https://opencode.ai/v1/docs/providers/
