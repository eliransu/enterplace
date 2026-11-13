# SDKs

OpenAI's and Anthropic's SDKs reach Gantry by their base URL. Give the client Gantry's address and a Gantry key in place of a provider key. Each request is then identified, decided, recorded and only then forwarded.

## At a glance

| SDK | Base URL | Variables | Route |
|---|---|---|---|
| OpenAI, Python | `base_url="http://127.0.0.1:8080/v1"` | `OPENAI_BASE_URL`, `OPENAI_API_KEY` | `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/models`, and `/v1/images/generations`, `/v1/audio/transcriptions`, `/v1/audio/speech`, `/v1/moderations`, `/v1/rerank` |
| OpenAI, TypeScript | `baseURL: "http://127.0.0.1:8080/v1"` | `OPENAI_BASE_URL`, `OPENAI_API_KEY` | the same |
| Anthropic, Python | `base_url="http://127.0.0.1:8080"` | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY` | `/v1/messages`, `/v1/messages/count_tokens` |
| Anthropic, TypeScript | `baseURL: "http://127.0.0.1:8080"` | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY` | the same |

The OpenAI SDKs take the address with `/v1`; the Anthropic SDKs take it without, because they add `/v1/messages` themselves.

The OpenAI SDKs send the key as `Authorization: Bearer`; the Anthropic SDKs send `api_key` (`ANTHROPIC_API_KEY`) as `x-api-key`, and `auth_token` (`ANTHROPIC_AUTH_TOKEN`) as `Authorization: Bearer`. Gantry reads either header; both at once must hold the same value, or the request is refused with `ambiguous_key`. Set only one of `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN`, to the Gantry key.

The model must be on a provider the route fits: chat, Responses and embeddings requests for models on an `openai` provider (chat also for `azure`, `gemini`, `vertex`), messages requests for models on an `anthropic` or `bedrock` provider. A request on the wrong route is refused with `wrong_route`, which names the right one. See [Providers](providers.html).

## Refusals

A refusal is an HTTP error, so each SDK raises its status error. The status picks the class: 400 `BadRequestError`, 401 `AuthenticationError`, 403 `PermissionDeniedError`, 404 `NotFoundError`, 429 `RateLimitError`, 500 and above `InternalServerError`, all subclasses of `APIStatusError` (Python) or `APIError` (TypeScript). The message ends with `Decision <id>.`, and every refusal also carries the decision ID in the `X-Gantry-Decision` header. Where the Gantry code sits depends on the SDK:

| SDK | Gantry code | Decision ID |
|---|---|---|
| OpenAI, Python | `e.code` | `e.body["decision"]` |
| OpenAI, TypeScript | `err.code` | `err.error.decision` |
| Anthropic, Python | `e.body["gantry_code"]` | `e.body["decision"]` |
| Anthropic, TypeScript | `err.error.gantry_code` | `err.error.decision` |

The OpenAI SDKs keep the inner `error` object of OpenAI's shape; the Anthropic SDKs keep the whole body of Anthropic's shape, where Gantry puts `gantry_code` and `decision` at the top level. The header works the same in all four: `e.response.headers["x-gantry-decision"]` in Python, `err.headers.get("x-gantry-decision")` in TypeScript. Every code is in [Refusal codes](refusals.html).

All four SDKs retry 408, 409, 429 and 5xx answers twice by default, but obey the `x-should-retry` header when it is there. Gantry sets it on every refusal: `false` on most, so a refusal is raised at once and recorded once; `true` on `busy`, `rate_limited` and the `upstream_*` codes, which the SDK sends again on its own. `max_retries` (Python) or `maxRetries` (TypeScript) changes the count.

## OpenAI SDK, Python

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=gantry_...
```

```python
import openai

client = openai.OpenAI()  # reads OPENAI_BASE_URL and OPENAI_API_KEY
try:
    answer = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Say hello."}],
    )
    print(answer.choices[0].message.content)
except openai.APIStatusError as e:
    print(e.status_code, e.code, e.body["decision"])
```

`openai.OpenAI(base_url=..., api_key=...)` sets both in code instead. `client.responses.create(...)` goes to `/v1/responses` and `client.embeddings.create(...)` to `/v1/embeddings`, for models on an `openai` provider.

## OpenAI SDK, TypeScript

```js
import OpenAI from "openai";

const client = new OpenAI(); // reads OPENAI_BASE_URL and OPENAI_API_KEY
try {
  const answer = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Say hello." }],
  });
  console.log(answer.choices[0].message.content);
} catch (err) {
  if (!(err instanceof OpenAI.APIError)) throw err;
  console.log(err.status, err.code, err.error?.decision);
}
```

`new OpenAI({ baseURL, apiKey })` sets both in code instead.

## Anthropic SDK, Python

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_API_KEY=gantry_...
```

```python
import anthropic

client = anthropic.Anthropic()  # reads ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY
try:
    message = client.messages.create(
        model="claude-sonnet-5-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Say hello."}],
    )
    print(message.content[0].text)
except anthropic.APIStatusError as e:
    print(e.status_code, e.body["gantry_code"], e.body["decision"])
```

`anthropic.Anthropic(base_url=..., api_key=...)` sets both in code instead. `e.type` holds Anthropic's error type for the code (for example `permission_error`), as listed in [Refusal codes](refusals.html).

## Anthropic SDK, TypeScript

```js
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic(); // reads ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY
try {
  const message = await client.messages.create({
    model: "claude-sonnet-5-5",
    max_tokens: 1024,
    messages: [{ role: "user", content: "Say hello." }],
  });
  console.log(message.content[0].text);
} catch (err) {
  if (!(err instanceof Anthropic.APIError)) throw err;
  console.log(err.status, err.error?.gantry_code, err.error?.decision);
}
```

`new Anthropic({ baseURL, apiKey })` sets both in code instead.

## Tested

- OpenAI SDK, Python: from docs only.
- OpenAI SDK, TypeScript: from docs only.
- Anthropic SDK, Python: from docs only.
- Anthropic SDK, TypeScript: from docs only.

None of the four SDKs is installed on the machine these pages were written on. The parameter, variable, exception and attribute names come from each SDK's documentation and published source. The refusal bodies they parse were checked against a running Gantry with `curl` on 2026-11-13, on both routes.

## Sources

Read on 2026-11-13:

- https://github.com/openai/openai-python/blob/main/README.md
- https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_client.py
- https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_base_client.py
- https://raw.githubusercontent.com/openai/openai-python/main/src/openai/_exceptions.py
- https://github.com/openai/openai-node/blob/master/README.md
- https://raw.githubusercontent.com/openai/openai-node/master/src/client.ts
- https://raw.githubusercontent.com/openai/openai-node/master/src/core/error.ts
- https://platform.claude.com/docs/en/api/sdks/python (served at https://platform.claude.com/docs/en/cli-sdks-libraries/sdks/python)
- https://platform.claude.com/docs/en/cli-sdks-libraries/sdks/typescript
- https://github.com/anthropics/anthropic-sdk-python/blob/main/README.md
- https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_client.py
- https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_base_client.py
- https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_error_classes.py
- https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/main/src/anthropic/_exceptions.py
- https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/core/error.ts
- https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/client.ts
