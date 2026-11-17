# Providers

A provider is a server Enterplace forwards to. Each one has a `kind`, which says the API it speaks and so which routes reach it:

| `kind` | API | Routes that reach it | Provider key sent as | Tested against |
|---|---|---|---|---|
| `openai` | OpenAI chat completions, Responses, embeddings | `POST /v1/chat/completions`, `POST /v1/responses`, `POST /v1/embeddings` | `Authorization: Bearer <key>` (none for a local server without `key_env`) | local mocks, and live with the OpenAI SDK's request shape against a mock; the vendors in the table below: their documentation and local mocks only |
| `anthropic` | Anthropic messages | `POST /v1/messages`, `POST /v1/messages/count_tokens` | `x-api-key: <key>` | local mocks, and live with the real Claude Code CLI against a mock |
| `azure` | Azure OpenAI chat completions | `POST /v1/chat/completions` | `api-key: <key>` | local mocks only |
| `bedrock` | Amazon Bedrock InvokeModel, Anthropic models | `POST /v1/messages` | AWS Signature Version 4, from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` | local mocks only (recorded fixtures of the documented format) |
| `gemini` | Google Gemini API generateContent | `POST /v1/chat/completions`, translated | `x-goog-api-key: <key>` | local mocks only |
| `vertex` | Gemini on Google Cloud Vertex AI | `POST /v1/chat/completions`, translated | `Authorization: Bearer <access token>` | local mocks only |
| `vertex_anthropic` | Claude on Google Cloud Vertex AI, rawPredict and streamRawPredict | `POST /v1/messages` | `Authorization: Bearer <access token>` | local mocks only |

No kind has been run against the real service in this release: no real provider keys were used. Report what you see against a real one.

A chat request for a model on an `anthropic` or `bedrock` provider is refused with `wrong_route`, naming the route to use, unless the provider says `accept_chat: true` (see [Translation](#translation-for-chat-clients)). A messages request for a model on an `openai`, `azure`, `gemini` or `vertex` provider is refused with `wrong_route`, unless the provider says `accept_messages: true` (see [Translation for Claude Code](#translation-for-claude-code)), and so is a Responses or embeddings request for a model on any provider but `openai`.

`GET /v1/models` answers in two shapes. A caller that sends `x-api-key` or `anthropic-version` (Anthropic's SDKs, Claude Code) gets Anthropic's list of the models the messages route reaches (`anthropic`, `bedrock`, `vertex_anthropic`, and any provider with `accept_messages: true`) that its rule allows. Any other caller (OpenAI's SDKs, Codex) gets OpenAI's list, `{"object":"list","data":[{"id":...,"object":"model","created":0,"owned_by":<provider>}]}`, of the models on the chat route (`openai`, `azure`, `gemini`, `vertex`) its rule allows. Both are recorded.

## Models

Each provider lists the exact model names it serves. A request goes to the one provider that lists its `model`. There is no wildcard and no alias. On `openai` and `anthropic` providers the name the client sends is the name the provider receives, because Enterplace forwards the body as it came. On `azure` and `bedrock` the name picks a deployment or a model ID from the provider's map (below), and the body is otherwise unchanged except as described there.

Write model names exactly as the vendor documents them, including any prefix such as `MiniMaxAI/MiniMax-M3` or tag such as `gpt-oss:20b`. In YAML, a list written as `[a, b]` holds names with `/`, `:` and `.` without quotes.

## How the URL is built

One rule, used by `enterplace check` and `enterplace serve` alike:

- `url` is `http` or `https`, a host, an optional port and an optional path. No login, query, fragment or spaces. A trailing `/` is ignored.
- A `url` without a path gets the route as it came: a chat request goes to `<url>/v1/chat/completions`, a messages request with `?beta=true` to `<url>/v1/messages?beta=true`.
- A `url` with a path is the vendor's base URL, which ends where `/v1` would. It gets the route after `/v1`: with `url: https://api.groq.com/openai/v1`, a chat request goes to `https://api.groq.com/openai/v1/chat/completions`.

So write the vendor's documented base URL as it is, or the part before `/v1`. Both `https://api.openai.com` and `https://api.openai.com/v1` reach `https://api.openai.com/v1/chat/completions`.

## OpenAI-compatible servers

Each example below was checked on 2026-11-13 against the vendor's public documentation (URL given), then tested with this version of Enterplace: `enterplace check` on the policy, and `enterplace serve` started on it. Enterplace was not run against the vendors themselves: no real provider keys were used. The route Enterplace calls was confirmed against a local mock: `POST <url>/v1/chat/completions` with `Authorization: Bearer <key>`.

Every example uses this rule, with the model changed:

```yaml
rules:
  - name: everyone
    principals: { any: true }
    models: [<the model>]
```

### Base URLs at a glance

Each `url` below is the vendor's documented OpenAI-compatible base URL, read on 2026-11-13 at the page given. All are `kind: openai`. "Routes" lists what the vendor's page says it serves of the three routes Enterplace forwards to `openai` providers; Enterplace forwards each route either way, and a route the vendor does not serve comes back as its 404.

| Vendor | `url` | Key | Routes the vendor documents | Docs read 2026-11-13 |
|---|---|---|---|---|
| Groq | `https://api.groq.com/openai/v1` | `key_env` | chat, Responses | https://console.groq.com/docs/openai |
| Mistral | `https://api.mistral.ai` | `key_env` | chat (embeddings on its own page) | https://docs.mistral.ai/api/ |
| Together AI | `https://api.together.ai/v1` | `key_env` | chat, Responses, embeddings | https://docs.together.ai/docs/openai-api-compatibility |
| Fireworks AI | `https://api.fireworks.ai/inference/v1` | `key_env` | chat (the page shows the base URL and SDK calls, not each path) | https://docs.fireworks.ai/tools-sdks/openai-compatibility |
| DeepSeek | `https://api.deepseek.com` | `key_env` | chat, at `/chat/completions` without `/v1` (see below) | https://api-docs.deepseek.com/ |
| OpenRouter | `https://openrouter.ai/api/v1` | `key_env` | chat, Responses | https://openrouter.ai/docs/quickstart |
| Ollama | `http://127.0.0.1:11434/v1` | none, with `allow_private: true` | chat, Responses (no `previous_response_id`), embeddings | https://docs.ollama.com/api/openai-compatibility |
| vLLM | `http://127.0.0.1:8000/v1` | none, or `key_env` with `vllm serve --api-key` | chat, Responses, embeddings | https://docs.vllm.ai/en/latest/serving/online_serving/ |
| LM Studio | `http://127.0.0.1:1234/v1` | none, with `allow_private: true` | chat, Responses, embeddings | https://lmstudio.ai/docs/app/api/endpoints/openai |

A `url` with a path gets the route after `/v1` (see above), so `https://api.fireworks.ai/inference/v1` reaches `https://api.fireworks.ai/inference/v1/chat/completions`. Tested against local mocks only: a path prefix (test `an_openai_compatible_server_on_a_path_prefix_gets_the_route_after_v1`) and a loopback server with no key, started from a policy file (`a_local_server_without_a_key_is_served_from_a_policy_file`). Enterplace was not run against the vendors.

A provider of kind `openai` whose `url` is on this machine or a private network (`allow_private: true`) may leave out `key_env`: no `Authorization` header is sent to it, and the caller's Enterplace key never is. Every other provider needs `key_env`.

### Works with this version

#### Ollama

Docs: https://docs.ollama.com/api/openai-compatibility. Base URL `http://localhost:11434/v1/`. The local server ignores the key, so Enterplace sends none.

```yaml
providers:
  - name: ollama
    kind: openai
    url: http://127.0.0.1:11434/v1
    allow_private: true
    models: [gpt-oss:20b]      # the name `ollama list` shows
```

From inside the container, `127.0.0.1` is the container itself. Use the host's address, for example `http://host.docker.internal:11434` with `--add-host host.docker.internal:host-gateway`, and keep `allow_private: true` if the address is private.

#### vLLM

Docs: https://docs.vllm.ai/en/latest/cli/serve/ and https://docs.vllm.ai/en/latest/serving/online_serving/. `vllm serve` listens on port 8000 and serves `/v1/chat/completions`. The model name clients send is `--served-model-name`, or the `--model` value if that is not set. `--api-key` makes vLLM require a key.

```yaml
providers:
  - name: vllm
    kind: openai
    url: http://127.0.0.1:8000
    allow_private: true
    key_env: VLLM_API_KEY      # the value given to vllm serve --api-key
    models: [local-llm]        # vllm serve <model> --served-model-name local-llm
```

#### Together AI

Docs: https://docs.together.ai/docs/openai-api-compatibility. Base URL `https://api.together.ai/v1`. Model names carry the organization: `MiniMaxAI/MiniMax-M3`. OpenAI names such as `gpt-4o` return 404 there.

```yaml
providers:
  - name: together
    kind: openai
    url: https://api.together.ai
    key_env: TOGETHER_API_KEY
    models: [MiniMaxAI/MiniMax-M3]
```

#### Mistral

Docs: https://docs.mistral.ai/api/. Server `https://api.mistral.ai`, chat at `POST /v1/chat/completions`.

```yaml
providers:
  - name: mistral
    kind: openai
    url: https://api.mistral.ai
    key_env: MISTRAL_API_KEY
    models: [mistral-small-latest, mistral-large-latest]
```

### Accepted by Enterplace, path not confirmed in current vendor docs

These start and forward, but the vendor's current page does not show the exact path Enterplace calls. Send one request through before relying on them.

#### DeepSeek

Docs: https://api-docs.deepseek.com/. Base URL `https://api.deepseek.com`, and the page's example posts to `https://api.deepseek.com/chat/completions`, without `/v1`. Enterplace calls `https://api.deepseek.com/v1/chat/completions`; the current page does not say whether that path is served. Models listed there: `deepseek-flash`, `deepseek-v4-pro`.

```yaml
providers:
  - name: deepseek
    kind: openai
    url: https://api.deepseek.com
    key_env: DEEPSEEK_API_KEY
    models: [deepseek-flash, deepseek-v4-pro]
```

#### xAI

Docs: https://docs.x.ai/docs/api-reference and https://docs.x.ai/docs/guides/chat. Base URL `https://api.x.ai/v1`. The current docs lead with the Responses API (`POST /v1/responses`), which Enterplace forwards to `openai` providers, and mention chat completions without giving its path. Enterplace calls `https://api.x.ai/v1/chat/completions`. Model in the examples: `grok-4.7`.

```yaml
providers:
  - name: xai
    kind: openai
    url: https://api.x.ai
    key_env: XAI_API_KEY
    models: [grok-4.7]
```

### Base URLs with a path

Each base URL was checked on 2026-11-13 against the vendor's documentation, and `enterplace check` and `enterplace serve` were run on each example. The path Enterplace calls was confirmed against a local mock with the same path (test `a_url_with_a_path_reaches_the_route_after_v1`). Enterplace was not run against the vendors.

#### Groq

Docs: https://console.groq.com/docs/openai. Base URL `https://api.groq.com/openai/v1`. Enterplace calls `https://api.groq.com/openai/v1/chat/completions`. Models: Groq's model IDs, as listed on its Models page.

```yaml
providers:
  - name: groq
    kind: openai
    url: https://api.groq.com/openai/v1
    key_env: GROQ_API_KEY
    models: [llama-3.3-70b-versatile]
```

#### OpenRouter

Docs: https://openrouter.ai/docs/quickstart. Base URL `https://openrouter.ai/api/v1`. Enterplace calls `https://openrouter.ai/api/v1/chat/completions`. Models are `vendor/model`, for example `anthropic/claude-sonnet-latest`; a leading `~` marks a latest alias, and YAML needs that name in quotes.

```yaml
providers:
  - name: openrouter
    kind: openai
    url: https://openrouter.ai/api/v1
    key_env: OPENROUTER_API_KEY
    models: [anthropic/claude-sonnet-latest]
```

#### Fireworks AI

Docs: https://docs.fireworks.ai/tools-sdks/openai-compatibility. Base URL `https://api.fireworks.ai/inference/v1`. Model names are account paths.

```yaml
providers:
  - name: fireworks
    kind: openai
    url: https://api.fireworks.ai/inference/v1
    key_env: FIREWORKS_API_KEY
    models: [accounts/fireworks/models/llama-v3p1-8b-instruct]
```

#### Gemini (OpenAI-compatible)

Docs: https://aistudio.google.com/docs/openai (moved from https://ai.google.dev/gemini-api/docs/openai). Base URL `https://generativelanguage.googleapis.com/v1beta/openai/`. Enterplace calls `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`, with the key in `Authorization: Bearer`.

```yaml
providers:
  - name: gemini
    kind: openai
    url: https://generativelanguage.googleapis.com/v1beta/openai/
    key_env: GEMINI_API_KEY
    models: [gemini-4-hydrogen]
```

The same rule fixes DeepSeek's path, whose page posts to `https://api.deepseek.com/chat/completions` without `/v1`: write `url: https://api.deepseek.com/v1` and Enterplace calls `https://api.deepseek.com/v1/chat/completions`. Whether DeepSeek serves that path is still not confirmed by its current page.

For tool calls, system instructions and Gemini's own usage counts, the native `gemini` kind below is the better choice.

## Gemini

```yaml
providers:
  - name: gemini
    kind: gemini
    url: https://generativelanguage.googleapis.com/v1beta
    key_env: GEMINI_API_KEY
    models: [gemini-2.5-flash, gemini-2.5-pro]
```

Callers use the chat route, `POST /v1/chat/completions`, as for any OpenAI model. Enterplace translates the request to Gemini's generateContent body and sends it to:

```text
POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent
POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse   (with "stream": true)
x-goog-api-key: <the value of GEMINI_API_KEY>
```

A `url` without a path gets `/v1beta`. What is translated (formats read 2026-11-13 at https://ai.google.dev/api/generate-content, now served at https://aistudio.google.com/api-reference/generate-content):

| Chat completions | Gemini |
|---|---|
| leading `system` and `developer` messages | `systemInstruction` |
| `user` text, images (base64 data URL or URL), PDF files (base64) | `contents` with role `user`: `text`, `inlineData`, `fileData` |
| `assistant` text and `tool_calls` | role `model`: `text` and `functionCall` (`id`, `name`, `args`) |
| `tool` messages | role `user`: `functionResponse` with the function's name, `response: {"content": <text>}` |
| `tools` (function) | `tools[0].functionDeclarations`, `parameters` as `parametersJsonSchema` |
| `tool_choice` `none`, `auto`, `required`, a named function | `toolConfig.functionCallingConfig` `NONE`, `AUTO`, `ANY`, `ANY` with `allowedFunctionNames` |
| `temperature`, `top_p`, `max_tokens`/`max_completion_tokens`, `stop`, `seed`, `presence_penalty`, `frequency_penalty` | `generationConfig` `temperature`, `topP`, `maxOutputTokens`, `stopSequences`, `seed`, `presencePenalty`, `frequencyPenalty` |
| `response_format` `json_object`, `json_schema` | `responseMimeType: application/json`, and `responseJsonSchema` |

The answer comes back as a `chat.completion` (text, `tool_calls`, `finish_reason` from Gemini's `finishReason`: `STOP` is `stop`, or `tool_calls` when the model called a function; `MAX_TOKENS` is `length`; the safety reasons are `content_filter`) with `usage` from `usageMetadata`. A stream comes back as `chat.completion.chunk` events ending in `data: [DONE]`, with a usage chunk when the request asked for `stream_options.include_usage`. A Gemini error comes back in OpenAI's error shape, its `status` (such as `RESOURCE_EXHAUSTED`) as the type.

A field that cannot be carried across is refused with `untranslatable`, naming it, as for the messages translation: for example `logprobs`, `n` above 1, `parallel_tool_calls: false`, `reasoning_effort`, audio, a tool with `strict: true`, or a system message after the conversation has started. Gemini's finish reasons that mean the answer failed, such as `MALFORMED_FUNCTION_CALL`, are reported the same way. The fields dropped on purpose (`user`, thought parts and others) are listed with their reasons in `enterplace_core::gemini::SAFE_TO_DROP`.

Usage records read Gemini's `usageMetadata`: prompt tokens are `promptTokenCount` plus `toolUsePromptTokenCount`, less `cachedContentTokenCount` (counted as cache reads); output tokens are `candidatesTokenCount` plus `thoughtsTokenCount`. Gemini prices are built in from the LiteLLM table (`enterplace prices gemini-2.5-pro`); `prices:` overrides them (see [Policy](policy.html)).

The request is checked by the guardrails, cached and counted against budgets in its chat form, then translated as it is sent, so a masked message is masked in what Gemini receives. A `gemini` provider can fall back to another `gemini` or a `vertex` provider, and to no other kind.

Limits: Gemini 3 models return a `thoughtSignature` with function calls and may ask for it back in the next turn; a chat client has no place to keep it, so it is dropped (multi-turn function calling on those models can end with `MISSING_THOUGHT_SIGNATURE`). `n` above 1, code execution, Google Search grounding and cached contents are not translated. Tested against a local mock only: no Google key was used.

## Vertex AI (Gemini)

```yaml
providers:
  - name: vertex
    kind: vertex
    url: https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google
    key_env: VERTEX_ACCESS_TOKEN     # export VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token)
    models: [gemini-2.5-pro]
```

The same translation as `gemini`, sent to `<url>/models/<model>:generateContent` (or `:streamGenerateContent?alt=sse`) with `Authorization: Bearer <token>`, the form in https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/function-calling (read 2026-11-13). The `url` must end in `/publishers/google`.

Limit: `key_env` holds an OAuth access token, which Google issues for about an hour, and Enterplace reads it at start. Enterplace does not sign in with a service account itself, so a token that expires means a restart with a new one. Tested against a local mock only.

## Vertex AI (Claude)

```yaml
providers:
  - name: claude-vertex
    kind: vertex_anthropic
    url: https://us-east5-aiplatform.googleapis.com/v1/projects/my-project/locations/us-east5/publishers/anthropic
    key_env: VERTEX_ACCESS_TOKEN     # export VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token)
    models: [claude-sonnet-4-6, claude-haiku-4-5]
```

Claude Code (or any messages client) reaches Claude on Vertex AI through Enterplace's `POST /v1/messages`. Enterplace sends the messages body to `<url>/models/<model>:rawPredict`, or `:streamRawPredict` when the body says `"stream": true`, with `model` removed (it is in the path) and `"anthropic_version": "vertex-2023-10-16"` added, and `Authorization: Bearer <token>`, the form in https://docs.cloud.google.com/vertex-ai/generative-ai/docs/partner-models/claude/use-claude (read 2026-11-13). The answer is Anthropic's own format, streamed or whole, and goes back unchanged. The `url` must end in `/publishers/anthropic`. `accept_chat: true` lets chat clients reach it too, translated, as for `anthropic`.

Vertex AI names models without Anthropic's date suffix (`claude-sonnet-4-6`). When Claude Code sends another name, map it with an alias: `aliases: [{ name: claude-sonnet-5-5, deployments: [{ provider: claude-vertex, model: claude-sonnet-4-6 }] }]`.

Limits: `POST /v1/messages/count_tokens` is refused with `wrong_route` for these models, as for Bedrock. `anthropic-beta` headers are passed on as sent; whether Vertex AI honours a beta is Vertex's to say. The access token is read at start and lasts about an hour, as for `vertex`. Tested against a local mock only: no Google credential was used.

## Anthropic

```yaml
providers:
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-5-5, claude-haiku-5-5]
```

Requests on the messages routes are forwarded as their original bytes. `anthropic-version` and `anthropic-beta` pass through unchanged, as does every `anthropic-*` and `x-claude-code-*` header. See [Claude Code](claude-code.html).

## Azure OpenAI

```yaml
providers:
  - name: azure
    kind: azure
    url: https://acme.openai.azure.com        # https://<resource>.openai.azure.com
    key_env: AZURE_OPENAI_API_KEY
    api_version: 2024-10-21
    models: [gpt-4o, gpt-4o-mini]
    deployments:                               # model name: deployment name
      gpt-4o: prod-gpt-4o
      gpt-4o-mini: prod-gpt-4o-mini
```

A chat request for `gpt-4o` goes to:

```text
POST https://acme.openai.azure.com/openai/deployments/prod-gpt-4o/chat/completions?api-version=2024-10-21
api-key: <the value of AZURE_OPENAI_API_KEY>
```

That is the form in the Azure OpenAI REST reference (https://learn.microsoft.com/en-us/azure/ai-foundry/openai/reference, read 2026-11-13), with the key in the `api-key` header. The body goes as it came, `model` included: the deployment in the path decides what runs. Every model in `models` needs an entry in `deployments`. `api_version` is a date, such as `2024-10-21`, or a date with `-preview`. A `url` with a path is put in front of `/openai/deployments/...`. Microsoft Entra tokens and Azure's newer `/openai/v1` API are not built.

## Amazon Bedrock (Claude)

```yaml
providers:
  - name: bedrock
    kind: bedrock
    region: us-east-1
    models: [claude-sonnet-5-5, claude-haiku-5-5]
    model_ids:                                 # model name: Bedrock model ID, inference profile ID or ARN
      claude-sonnet-5-5: us.anthropic.claude-sonnet-5-5-v1:0
      claude-haiku-5-5: us.anthropic.claude-haiku-5-5-v1:0
```

```sh
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # and AWS_SESSION_TOKEN for temporary credentials
enterplace serve enterplace.policy.yaml
```

The model IDs above are examples: use the IDs your account has access to, from the Bedrock console. Enterplace reads the access key from its own environment, as the AWS SDKs do; it never runs the `aws` command and reads no AWS config file. A bedrock provider takes no `key_env`. `url` is optional and defaults to `https://bedrock-runtime.<region>.amazonaws.com`; set it for a VPC endpoint.

A request on `/v1/messages` for `claude-sonnet-5-5` goes to InvokeModel, or to InvokeModelWithResponseStream when the body says `"stream": true`:

```text
POST https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-sonnet-5-5-v1%3A0/invoke
POST https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-sonnet-5-5-v1%3A0/invoke-with-response-stream
```

The body is changed as Bedrock's Anthropic documentation says (https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages-request-response.html, read 2026-11-13): `model` and `stream` are removed (the path carries both), `anthropic_version: bedrock-2023-05-31` is added, and the values of the `anthropic-beta` header become the `anthropic_beta` list. Every other field goes as it came. The request is signed with AWS Signature Version 4 (service `bedrock`), implemented in Enterplace and tested against AWS's published test vectors.

Bedrock streams its answer as an AWS event stream. Enterplace checks each message's checksums and turns each `chunk` into the Anthropic server-sent event it holds, so Claude Code and Anthropic's SDKs read it unchanged. A Bedrock error, streamed or not, reaches the caller in Anthropic's error shape with Bedrock's message, for example `{"type":"error","error":{"type":"invalid_request_error","message":"Amazon Bedrock ValidationException: ..."}}`.

Limits: `/v1/messages/count_tokens` is refused with `wrong_route` for a bedrock model (Enterplace does not call Bedrock's CountTokens). Betas are passed on as sent: a beta Bedrock does not offer comes back as Bedrock's 400. Tested against a local mock only: no AWS account was used.

## Retries and fallbacks

```yaml
providers:
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-5-5]
    retries: 2              # up to 2 more tries on this provider
    fallback: bedrock       # then bedrock, with its own retries
  - name: bedrock
    kind: bedrock
    region: us-east-1
    models: [claude-haiku-5-5]
    model_ids:
      claude-haiku-5-5: us.anthropic.claude-haiku-5-5-v1:0
      claude-sonnet-5-5: us.anthropic.claude-sonnet-5-5-v1:0   # serves the fallback
```

Before the first byte of an answer reaches the caller, these are tried again: a connection failure, a timeout (120 seconds without an answer), a 429 and any 5xx. A provider is tried `retries` more times (0 to 5, default 0), waiting 200 ms, 400 ms, 800 ms and so on between tries. If every try fails, the request goes to `fallback` with that provider's own `retries`. A fallback's own `fallback` is not followed. If the fallback fails too, the caller gets the last answer or refusal.

Once any byte of an answer has gone to the caller, nothing is tried again: a stream that breaks halfway breaks for the caller. A caller's own error, any 4xx other than 429, is never retried and never sent to the fallback.

The fallback must take the same requests (`anthropic` and `bedrock` take messages, `openai` and `azure` take chat completions, `gemini` and `vertex` take translated chat completions) and serve each model of the provider it backs: under the same name on `openai` and `anthropic`, or through its `deployments` or `model_ids` on `azure` and `bedrock`. It does not list those models in its `models`: a model is still served by one provider. `enterplace check` refuses a fallback that does not exist, names itself, speaks the other API or has no name for one of the models.

The request record is written before anything is sent, so it names the first provider. When more than one try was made, a second record with the same `id` follows it:

```json
{"n":12,"event":"attempts","id":"01M7...","time":"2026-11-13T03:30:02.114Z","attempts":[{"provider":"anthropic","outcome":"529"},{"provider":"anthropic","outcome":"529"},{"provider":"anthropic","outcome":"529"},{"provider":"bedrock","outcome":"200"}],"prev":"...","hash":"..."}
```

`outcome` is the provider's status, or the refusal code for a try that got no answer (`upstream_unreachable`, `upstream_failed`, `upstream_timeout`). `enterplace audit verify` counts these as attempts records. The request's usage record follows when the answer ends, and names the provider that answered. `retries`, `fallback`, `accept_chat`, `deployments` and `model_ids` change without a restart; `region` and `api_version` need one.

## Aliases and load balancing

An alias is a model name callers send that Enterplace serves from one or more deployments: a provider and the model it is sent to there. It is listed under `aliases:` at the top level of the policy file.

```yaml
aliases:
  - name: smart                       # what callers send as "model"
    balance: round_robin              # or least_busy; default round_robin
    cooldown_seconds: 30              # default 30, 0 to 3600
    context_window_fallback: gpt-4o-long   # optional: a model or another alias
    content_policy_fallback: claude-safe   # optional
    deployments:
      - { provider: openai-east, model: gpt-4o, weight: 2 }
      - { provider: openai-west, model: gpt-4o }          # weight 1
```

- **Rules decide on the name the caller sent.** A rule lists `smart`, not each deployment, and `/v1/models` lists `smart` to whoever the rule allows. An admin who wants a person to reach only one deployment gives them a model name, not the alias. This keeps one decision per request and keeps a policy readable when deployments change.
- **Picking.** `round_robin` takes the deployments in turn, each as often as its `weight` (1 to 1000). `least_busy` takes the one with the fewest requests in flight through this Enterplace process, counted until the answer has been passed on. The other deployments follow in the order written.
- **Cooldown.** A deployment that fails (no connection, a timeout, a 429 or a 5xx) is passed over for `cooldown_seconds`, and the request goes on to the next deployment at once, with each provider's own `retries`. A deployment that answers is in turn again. When every deployment is cooling down, they are still tried, in order: an alias never refuses a request only because each deployment failed once. Cooldown and the in-flight count are kept in memory, per process, across reloads.
- **The model sent.** The `model` of a deployment is the name sent to that provider: the JSON body's `model` is replaced with it (the form field `model` for an audio upload), and nothing else in the body changes. It need not be listed in the provider's `models` (listing it also lets callers ask for it by name). For `azure` and `bedrock` it must be a key of the provider's `deployments` or `model_ids`.
- **Same API.** All deployments of an alias speak the same API (`openai` and `azure`, `anthropic` and `bedrock`, `gemini` and `vertex`); `enterplace check` refuses a mix, an unknown provider, a missing map entry, a weight out of range and an alias that has the name of a model a provider lists.
- **Named fallbacks.** When a deployment answers 4xx with a context window error (OpenAI's `context_length_exceeded`, Anthropic's "prompt is too long", or a message that names the maximum context length), the request is sent to `context_window_fallback`. When it answers with a content policy error (`content_policy_violation` or Azure's `content_filter`), it goes to `content_policy_fallback`. Each names a model a provider serves or another alias, taking the same API and translation as the request; its own fallbacks are not followed. The error answer is read whole only when the alias names such a fallback. Any other 4xx goes to the caller unchanged.
- **Records.** The decision record keeps `model` as the alias the caller sent and the rule decided on, `provider` as the first deployment's provider, and adds `"alias": "smart"` and `"deployment": "openai-east/gpt-4o"`. When more than one deployment was tried, the `attempts` record names each as `provider/model`. The usage record names the provider and model that answered, and the answer is charged at that model's price; a budget reserves at the price of the first deployment picked. A rule with a budget that names an alias needs a price for each deployment's model.

Aliases change without a restart, as rules do.

## Translation for chat clients

A provider of kind `anthropic` or `bedrock` may say `accept_chat: true`. A chat completions request for one of its models is then translated to the messages format, sent, and its answer translated back: a whole answer to a `chat.completion`, a stream to `chat.completion.chunk` events ending in `data: [DONE]`, with a final usage chunk when the request asked for `stream_options.include_usage`. Errors come back in OpenAI's error shape. A translated request to an `anthropic` provider carries `anthropic-version: 2023-06-01`.

```yaml
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-5-5]
    accept_chat: true
```

A field that cannot be carried across is refused with `untranslatable`, naming it, and never dropped. For example `"n": 2`:

```text
Refused (untranslatable): The parameter "n" set to 2 has no equivalent in Anthropic's messages API, so Enterplace cannot translate it. Remove it, or use a model whose provider speaks the client's format. Decision 01M7....
```

The translation is decided before the record is written, so an untranslatable request is a recorded refusal. The record of a translated request says `"translated": true`. The few fields dropped on purpose (such as `seed` and thinking blocks) are listed with their reasons in `enterplace_core::translate::SAFE_TO_DROP`. Without `accept_chat`, chat requests for these models are refused with `wrong_route` as before. Messages requests are translated the other way only for a provider with `accept_messages: true`, below.

## Translation for Claude Code

A provider of kind `openai`, `azure`, `gemini` or `vertex` may say `accept_messages: true`. A messages request (Claude Code, an Anthropic SDK) for one of its models is then translated to a chat completions request, sent (to Gemini and Vertex AI translated once more, to generateContent), and its answer translated back to the messages format:

- A whole answer becomes a `message`: text and `tool_use` blocks (tool call arguments parsed to `input`), `stop_reason` from `finish_reason` (`stop` to `end_turn`, `length` to `max_tokens`, `tool_calls` to `tool_use`, `content_filter` or a refusal to `refusal`), and usage.
- A stream becomes Anthropic's events, in the order Claude Code reads them: `message_start`, then for each text or tool call `content_block_start`, `content_block_delta` (`text_delta`, or `input_json_delta` for tool arguments) and `content_block_stop`, then `message_delta` with `stop_reason` and usage, then `message_stop`. Enterplace asks the provider for `stream_options.include_usage`, so the usage record and `message_delta` carry the provider's counts. A provider error in the stream becomes an `error` event; a stream cut before `data: [DONE]` is broken off, not ended as if complete.
- Errors come back in Anthropic's error shape, the type chosen by status (429 is `rate_limit_error`), with the message `Provider "<name>" answered <status>: <the provider's message> Decision <id>.`, the decision ID in `decision`, the provider's own `Retry-After`, and `x-should-retry: true` for 408, 409, 429 and 5xx (`false` otherwise), so Claude Code retries only what may clear.
- System prompts, images (base64 or URL), tools and tool results, `tool_choice`, `stop_sequences`, `temperature`, `top_p`, `metadata.user_id` (sent as `safety_identifier`; one longer than OpenAI's 64 characters, such as Claude Code's, is sent as its SHA-256) and `output_config.effort` (sent as `reasoning_effort`) are carried over.

```yaml
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_PROVIDER_KEY
    models: [gpt-5]
    accept_messages: true
```

What is refused with `untranslatable`, by name: thinking of type `enabled` (adaptive thinking is let through: the model decides), server tools (web search, code execution), `context_management` edits other than clearing thinking, document and other non-text tool result blocks, and any field Enterplace does not know. Dropped on purpose, with reasons in `SAFE_TO_DROP`: `cache_control`, thinking blocks, `defer_loading` on tools, `context_management` that only clears thinking, and the `anthropic-*` headers. `count_tokens` for these models is refused with `wrong_route`.

Limit: Claude Code sends `output_config.effort` (as `reasoning_effort`) on every request. A model that is not a reasoning model may refuse that field; the provider's 400 then reaches Claude Code as it was given. Tested with the real Claude Code CLI (2.1.323) against a mock OpenAI chat server, including a Bash tool call and its result; never against a real OpenAI, Gemini or Vertex model.

## Responses and embeddings

`POST /v1/responses` (OpenAI's Responses API, which Codex CLI and newer OpenAI SDKs use) and `POST /v1/embeddings` go to the `openai` provider that lists the request's `model`, as their original bytes, to `<url>/v1/responses` and `<url>/v1/embeddings` (after `/v1` for a `url` with a path). They are governed as chat requests are: identified, decided by the rule for `model`, checked by the guardrails, cached, rate limited and counted against budgets, recorded before they are sent, retried and sent to the fallback the same way. The guardrails read the Responses `instructions` and every `input` text (a string, or `input_text` parts of input messages) and the embeddings `input` (a string or a list of strings; token ID arrays are not text and are not checked).

Usage records read the Responses `usage` (`input_tokens` less `input_tokens_details.cached_tokens` and `cache_write_tokens`, which are counted apart, and `output_tokens`), from the whole answer or, for a stream, from the `response` in its `response.completed` event (or `response.incomplete` or `response.failed`). Embeddings report `usage.prompt_tokens`. A Responses request's `max_output_tokens` sizes its budget reservation. Formats read 2026-11-13: https://developers.openai.com/api/reference/resources/responses/methods/create, https://developers.openai.com/api/reference/resources/responses/streaming-events, https://developers.openai.com/api/reference/resources/embeddings/methods/create.

Not built: the other Responses routes (`GET` and `DELETE /v1/responses/{id}`, input items, cancel), which are refused with `unknown_route`. A request with `previous_response_id` or `store: true` leaves the conversation stored at OpenAI under Enterplace's provider key: the record shows the request, and Enterplace does not track what the provider stored.

## Images, audio, moderations and rerank

These routes go to the `openai` provider that serves the request's `model` (or an alias's deployment), as their original bytes, to the same path under its `url`:

| Route | Body | Model read from | Guardrails read | Usage and cost |
|---|---|---|---|---|
| `POST /v1/images/generations` | JSON | `model` | `prompt` (a string; any other shape is refused under a rule with guardrails) | `usage` when the provider reports it (gpt-image models), else `per_image` times the number of images in `data` |
| `POST /v1/audio/transcriptions` | `multipart/form-data`, parsed strictly and forwarded byte for byte with its boundary (masked text fields written back in place) | the one form field named `model` | every text field but `model` (such as `prompt`); not the audio | `usage` when reported (gpt-4o transcribe models); otherwise the reservation, as for any answer without usage |
| `POST /v1/audio/speech` | JSON; the answer is audio, passed through as it arrives | `model` | `input` and `instructions` (strings; any other shape is refused under a rule with guardrails) | none reported: charged its reservation under a budget |
| `POST /v1/moderations` | JSON | `model` (required here: the policy decides on it) | `input`: a string, a list of strings, or `text` items (`image_url` items are not text); any other item is refused under a rule with guardrails | none reported |
| `POST /v1/rerank` | JSON, Cohere style, for an `openai` provider that serves it (vLLM, Cohere's compatible endpoint and others) | `model` | every string in `query` and in each document, a structured document's fields included (Cohere's `rank_fields`) | none reported |

Each is governed as chat requests are: identified, decided by the rule for its `model`, recorded before it is sent, rate limited, counted against budgets and tokens per minute, retried and sent to fallbacks. A request with no `model` is refused with `unreadable_request`, including a moderation request, which OpenAI would otherwise send to its default model. A form with no `model` field, or with two, is refused the same way.

The form of a transcription is parsed strictly, so the field Enterplace decides on is the one every standard parser reads: the body starts with its boundary, every other boundary starts a line, each part has one Content-Disposition with plain `name="..."` and `filename="..."` parameters, and the content type has one boundary. A form with an extended `name*=` parameter, spaces around `=`, a backslash or single quotes in a parameter, a folded header line, or bytes after the closing boundary is refused with `unreadable_request`.

Under a rule with guardrails, a transcription's text fields (`prompt` and the like) are checked as any text is, and what a mask changes is written back into the form; the audio itself is not read. A form with no text field is forwarded, and its record says `"guardrails": "not_run: the body is audio"` rather than that the guardrails found nothing. A rule whose guardrails must see what is spoken should not be given transcription models.

Images are priced by the image with `per_image` under `prices:` (US dollars per image, for example `dall-e-3: { input: 0, output: 0, per_image: 0.04 }`): a budget reserves `n` (default 1) times it, and the answer is charged for each image it holds. An image model priced by the token (gpt-image) and a speech model priced by the token bill what they generate as output tokens, which no request field bounds: under a budget or a tokens-per-minute limit such a request needs `max_output` in the model's price, and reserves `n` times it; without `per_image` or `max_output` it is refused with `max_tokens_needed`. Prices of text routes are as before.

Formats follow (not re-read for this version; check before release): https://platform.openai.com/docs/api-reference/images/create, https://platform.openai.com/docs/api-reference/audio/createTranscription, https://platform.openai.com/docs/api-reference/audio/createSpeech, https://platform.openai.com/docs/api-reference/moderations/create, https://docs.cohere.com/reference/rerank.

Not built: image edits and variations, audio translations, batches and files. They are refused with `unknown_route`.

## What reaches the provider

- The body, byte for byte, except for a translated request (Gemini, Vertex AI, `accept_chat`), a request to Bedrock, and a request for an alias, whose `model` is replaced with the deployment's, as described above.
- The path, and only the query parameters the route allows, with an allowed value (`beta=true` or `beta=false` on the messages routes, none on chat, Responses and embeddings).
- The caller's headers, except: hop-by-hop headers, `Host`, `Cookie`, any header whose name contains `authorization`, `key`, `token`, `secret`, `organization` or `project` (except `idempotency-key`), any header starting with `x-amz`, and any header that carries the caller's Enterplace key.
- The provider key, in the header its kind expects, or the AWS signature for Bedrock, or nothing for a local `openai` provider without `key_env`.

The provider's answer, including its errors and streamed events, returns unchanged except for hop-by-hop headers, with `X-Enterplace-Decision` and a `Server-Timing: enterplace;dur=<ms>` entry added. Bedrock's answers and translated answers are converted as described above.
