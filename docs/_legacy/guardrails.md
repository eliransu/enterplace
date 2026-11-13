# Guardrails

A rule names the guardrails that check the text of each request it allows, after the policy decision and before the record is written and the request is sent. They run in the order the rule lists them: the built-in detectors first, then each remote guardrail. Once one blocks, no further remote guardrail is asked.

Every guardrail is one of three kinds:

- **Built in**, run inside Gantry: `secrets` and `pii`. See [Policy file](policy.html#guardrails).
- **Webhook**: any service that speaks Gantry's contract. See [Guardrail webhooks](guardrail-webhook.html).
- **Vendor**, a service Gantry speaks to in its own API, so no adapter is needed: `openai_moderation`, `presidio`, `lakera`, `bedrock_guardrail`, `azure_content_safety`, `azure_prompt_shield` and `llama_guard`.

## What every remote guardrail shares

| Field | Meaning |
|---|---|
| `name` | Named by rules, and in every record. |
| `type` | One of the types above. |
| `action` | `block` (the default) obeys the service: it refuses, or masks when the service masks. `warn` only records what the service found. `mask` is taken by `presidio` only. |
| `url` | The service. `https://`, or `http://` on 127.0.0.1 or localhost only, because prompts in clear text across a network are a leak of their own. Optional where the vendor has one public address. |
| `timeout_ms` | 1 to 30000, default 1000. It covers every call the guardrail makes for one request. |
| `on_failure` | Required. `fail_closed` refuses the request when the service cannot answer in time, answers with an error status, or answers something Gantry cannot read; `fail_open` sends the request and records that the check did not run (`kind: unavailable`, `action: skipped`). |
| `key_env` | The name of the environment variable that holds the vendor's API key. The key itself never goes in the policy file. |
| `headers_env` | Extra headers from environment variables, for a proxy in front of the vendor. Same rules as for a webhook. |

Credentials are read from the environment when a call is made. Gantry does not start, and a reload is refused, while a variable a guardrail names is unset. No credential, no matched text and no vendor message reaches a record, a log line or a refusal: a record holds the guardrail, the vendor (`detector`), the kind of finding, the action and a count.

```yaml
guardrails:
  - name: moderation
    type: openai_moderation
    key_env: OPENAI_API_KEY
    on_failure: fail_open
    timeout_ms: 800
```

## The vendors

### openai_moderation

OpenAI's moderation endpoint, `POST {url}/moderations`, default `url` `https://api.openai.com/v1`, `Authorization: Bearer` from `key_env` (required). Each text of the request is one input. `model` is optional (OpenAI's default is `omni-moderation-latest`). A flagged result blocks; each category set to true is a finding, such as `violence`, `harassment_threatening` (a `/` in a category becomes `_`), on the message it was found in. Cannot mask.

### presidio

Microsoft Presidio, self-hosted. `url` is the analyzer (`POST {url}/analyze`), required. No key: run it next to Gantry or behind a proxy that adds one through `headers_env`. The messages are sent as one text, in English. Each entity found is a finding of its type, lowercased (`email_address`, `person`, `phone_number`).

- `action: block` refuses when anything is found; `warn` records it.
- `action: mask` needs `anonymizer_url`: Gantry sends the text and the analyzer's results to `POST {anonymizer_url}/anonymize`, which replaces each entity with `[MASKED email_address]` and the like, and forwards the masked request.

```yaml
guardrails:
  - name: presidio-mask
    type: presidio
    url: http://127.0.0.1:5002
    anonymizer_url: http://127.0.0.1:5001
    action: mask
    on_failure: fail_closed
```

A message that holds the character U+001E cannot be checked (Gantry joins the messages with it) and counts as a failure of the service.

### lakera

Lakera Guard, `POST {url}/v2/guard`, default `url` `https://api.lakera.ai`, `Authorization: Bearer` from `key_env` (required). The messages go as chat messages with `breakdown: true`; `project_id` picks the Lakera project and so its policy. `flagged: true` blocks; each detector that detected something is a finding of its `detector_type` on its message. A project in Detect mode never flags, so it never blocks. Cannot mask.

```yaml
guardrails:
  - name: injection
    type: lakera
    key_env: LAKERA_GUARD_API_KEY
    project_id: project-1234567890
    on_failure: fail_closed
```

### bedrock_guardrail

An Amazon Bedrock guardrail through ApplyGuardrail, `POST {url}/guardrail/{guardrail_id}/version/{guardrail_version}/apply` with `source: INPUT`, signed with AWS Signature Version 4. `region`, `guardrail_id` and `guardrail_version` (a number, or `DRAFT`) are required; `url` defaults to `https://bedrock-runtime.{region}.amazonaws.com`. The access key is read from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and, for temporary credentials, `AWS_SESSION_TOKEN`, as for a Bedrock provider; the guardrail takes no `key_env`.

`NONE` allows. `GUARDRAIL_INTERVENED` blocks, with a finding for each policy entry that acted: a denied topic's name, a content filter's type (`hate`, `prompt_attack`), a sensitive information type (`email`, or a regex's name), a managed word list's type, or `custom_word` (the matched word is never read). When every entry was anonymized and Bedrock gave back one text per text sent, the request is masked with Bedrock's texts instead; otherwise it is refused rather than sent unmasked. `action: mask` is not taken: the guardrail's own configuration in AWS decides what to mask.

```yaml
guardrails:
  - name: bedrock
    type: bedrock_guardrail
    region: us-east-1
    guardrail_id: abc123def456
    guardrail_version: "1"
    on_failure: fail_closed
    timeout_ms: 1500
```

### azure_content_safety

Azure AI Content Safety text analysis, `POST {url}/contentsafety/text:analyze?api-version=2024-09-01`, `url` the resource's endpoint (required), `Ocp-Apim-Subscription-Key` from `key_env` (required). The messages are joined and sent in pieces of 10,000 characters, the most Azure reads at once, one call each, all within `timeout_ms`. A category whose severity is at least `threshold` (0 to 7, default 4, which is medium) is a finding: `hate`, `selfharm`, `sexual`, `violence`. Cannot mask.

### azure_prompt_shield

Azure AI Content Safety Prompt Shields, `POST {url}/contentsafety/text:shieldPrompt?api-version=2024-09-01`, same `url` and `key_env`. The last user message is the prompt; every other user message and every tool result is a document, where an indirect attack would hide. System and assistant text are not sent. A detected attack is `prompt_injection` (the prompt) or `indirect_prompt_injection` (a document), on its message. Cannot mask.

```yaml
guardrails:
  - name: shields
    type: azure_prompt_shield
    url: https://contoso-safety.cognitiveservices.azure.com
    key_env: AZURE_CONTENT_SAFETY_KEY
    on_failure: fail_closed
```

### llama_guard

A model behind an OpenAI-compatible chat completions API used as a classifier, `POST {url}/chat/completions` with `temperature: 0`. `url` and `model` are required, `key_env` (sent as `Authorization: Bearer`) is optional for a local server.

- Without `prompt`, the conversation is sent as user and assistant turns, as a Llama Guard model expects: its chat template writes the classification prompt and its categories.
- With `prompt`, any chat model can classify: the prompt is sent as one user message with `{conversation}` replaced by the messages (`User: ...`, `Agent: ...`). The prompt must ask for the answer format below.

The first line of the answer must be `safe` (allow) or `unsafe` (block); a second line of comma-separated categories gives the findings (`s1`, `s10`). Any other answer counts as a failure of the service and follows `on_failure`. The model's words are never recorded. Cannot mask.

```yaml
guardrails:
  - name: llama-guard
    type: llama_guard
    url: http://127.0.0.1:8000/v1
    model: meta-llama/Llama-Guard-3-8B
    on_failure: fail_closed
    timeout_ms: 3000
  - name: classifier
    type: llama_guard
    url: https://api.openai.com/v1
    key_env: OPENAI_API_KEY
    model: gpt-4o-mini
    prompt: |
      You check messages sent to an AI assistant at a bank. Answer "safe" on the first line if the last
      message is fine. Otherwise answer "unsafe" on the first line and the reasons on the second, comma
      separated, from: fraud, injection, offtopic.

      {conversation}
    on_failure: fail_open
```

## A whole policy

```yaml
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com/v1
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
guardrails:
  - name: no-secrets
    type: secrets
    action: block
  - name: moderation
    type: openai_moderation
    key_env: OPENAI_API_KEY
    on_failure: fail_open
  - name: injection
    type: lakera
    key_env: LAKERA_GUARD_API_KEY
    on_failure: fail_closed
rules:
  - name: everyone
    principals: { any: true }
    models: ["*"]
    guardrails: [no-secrets, moderation, injection]
```

## Checking the answer

A guardrail reads requests unless it says otherwise. `on:` picks what it reads:

```yaml
guardrails:
  - name: no-secrets-out
    type: secrets
    action: block
    on: [answer]            # or [request, answer]; without on: requests only
  - name: no-pii-out
    type: pii
    action: mask
    on: [answer]
```

On the answer, a guardrail reads the model's text in a whole answer, before it reaches the caller: a chat completion's `choices[].message.content` and tool call arguments, a message's `text` blocks, a Responses answer's output text. Every type works there: the built-in `secrets` and `pii`, a webhook and each vendor, shown the text as assistant messages.

- `block` replaces the answer with a 403 `guardrail_blocked` refusal: `Refused: guardrail "no-secrets-out" withheld the model's answer, which contained aws_access_key (1). ...`. The model's words are not shown or recorded. The answer was produced, so its usage record still counts it.
- `mask` rewrites the text in the answer, as on requests, and `warn` records only.
- Each checked answer gets an `answer_guardrails` record after the request's own record, with the same `id` (the decision ID), `verdict` (`block`, `mask` or `pass`) and what each guardrail found, never the text. The answer is passed on only once that record is written.
- Errors from the provider are not checked: they are its words, not the model's. A cached answer is checked like a fresh one.

**Streamed answers are checked only on a rule with `buffer_stream: true`.** By default a stream is passed on as it arrives, and its `answer_guardrails` record says `verdict: not_run` and `guardrails: "not_run: the answer is streamed"`, so the log never suggests a streamed answer was checked. Claude Code and most coding agents stream, so a rule that must check every answer sets:

```yaml
guardrails:
  - name: no-secrets-out
    type: secrets
    action: block
    on: [answer]
rules:
  - name: platform-team
    principals: { team: platform }
    models: ["*"]
    guardrails: [no-secrets-out]
    buffer_stream: true
```

Gantry then holds the whole stream (up to 64 MiB), reads the text its events carry (chat chunks' `delta.content` and tool call arguments, messages' text deltas, Responses' `output_text` deltas, joined, so a secret split across events is found), and runs the answer guardrails on it. Allowed, the events go out exactly as the provider sent them. Masked, they go out as a stream with the masked text in the first event of each text and the later events of that text empty. Blocked, the caller gets the same 403 `guardrail_blocked` refusal as for a whole answer, in its own error shape, and none of the stream. The cost is latency: the caller sees no token until the model has written its last, so a long answer that would have started streaming in under a second arrives all at once. `gantry check` refuses `buffer_stream: true` on a rule whose guardrails have no `on: [answer]`.

## What is not checked

- **Streamed answers** on a rule without `buffer_stream`, above.
- What the built-in detectors do not read (tool arguments, images, files): see [Security](security.html).
- Presidio is asked in English only.

## Sources

Each vendor's format was read from its public documentation on 2026-11-13:

- OpenAI moderations: https://developers.openai.com/api/reference/resources/moderations/methods/create
- Presidio: https://presidio.dataprivacystack.org/getting_started/getting_started_text/ and https://presidio.dataprivacystack.org/installation/
- Lakera Guard: https://docs.lakera.ai/docs/api/guard and https://docs.lakera.ai/api-reference/lakera-api/guard/screen-content
- Amazon Bedrock ApplyGuardrail: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ApplyGuardrail.html
- Azure AI Content Safety: https://learn.microsoft.com/en-us/rest/api/contentsafety/text-operations/analyze-text?view=rest-contentsafety-2024-09-01 and https://learn.microsoft.com/en-us/rest/api/contentsafety/text-operations/shield-prompt?view=rest-contentsafety-2024-09-01
- Llama Guard 3: https://dev.meta.ai/llama/docs/model-cards-and-prompt-formats/llama-guard-3/
