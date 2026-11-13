# Guardrail webhook contract

A `webhook` guardrail lets an outside service check each request before Gantry sends it to a provider:
a guardrail vendor's service that speaks this contract, a vendor behind a small adapter, or a company's own service.
This page is everything a vendor needs to build against it. The types live in `crates/gantry-core/src/guard.rs`.

## Policy file

```yaml
guardrails:
  - name: no-secrets
    type: secrets          # built in
    action: block          # block | mask | warn
  - name: mask-pii
    type: pii              # built in
    action: mask
  - name: vendor
    type: webhook
    url: https://guard.example.com/v1/check
    timeout_ms: 300        # 1 to 30000, default 1000
    on_failure: fail_closed  # required: fail_closed | fail_open
    action: block          # optional: block (obey the answer, default) | warn (record only)
    headers_env:           # optional: headers to send, each from an environment variable
      Authorization: GUARD_TOKEN

rules:
  - name: everyone
    principals: { any: true }
    models: ["*"]
    guardrails: [no-secrets, mask-pii, vendor]
```

- The url must be `https://`. Plain `http://` is accepted only for `localhost`, `127.0.0.1` or `[::1]` (a sidecar on the same machine).
- `on_failure` has no default, because it is a security choice. `fail_closed` refuses the request when the service is unreachable, slow, answers with an error status or sends a malformed answer. `fail_open` forwards the request and records that the check did not run (audit action `skipped`).
- `headers_env` maps a header name to the environment variable that holds its value, for a service that wants a credential. Put the whole value in the variable (for example `export GUARD_TOKEN="Bearer abc..."`). The value is never in the policy file, never in an audit record (the `config_loaded` record holds the variable's name only) and never shown. `gantry serve` does not start, and a reload is rejected, while a named variable is unset. Header names Gantry sets itself (`Host`, `Content-Type`, `Content-Length` and the connection headers) are refused by `gantry check`.
- `action: warn` is a monitor mode for rollouts: the answer is recorded and never enforced.
- Built-in guardrails run first. A webhook sees the request after built-in masking, so it never receives text Gantry already masked. If a built-in guardrail blocks, no webhook is called.

## Request

Gantry calls the service with the same HTTP client it uses for providers (HTTP/1.1, connections reused, public TLS roots), once per request the rule allows. It sends only the headers `headers_env` names, and forwards none of the caller's headers. Gantry sends `POST <url>` with `Content-Type: application/json` and this body, and nothing else:

```json
{
  "decision_id": "01JD3X6Q8M2T4V9W0Y1Z3A5B7C",
  "person": "maya.cohen",
  "team": "payments",
  "model": "gpt-4o-mini",
  "route": "/v1/chat/completions",
  "messages": [
    { "role": "system", "text": "You are a support assistant." },
    { "role": "user", "text": "My card is 4111 1111 1111 1111, why was it declined?" }
  ]
}
```

| Field | Meaning |
|---|---|
| `decision_id` | The ID of Gantry's policy decision and audit record for this request. Log it to correlate your records with Gantry's. |
| `person` | The name of the Gantry key that sent the request: a person or a workload. |
| `team` | That key's team. |
| `model` | The model the request asks for. |
| `route` | The Gantry route: `/v1/chat/completions` (OpenAI format) or `/v1/messages` (Anthropic format). |
| `messages` | Every text part of the request, in order: the system prompt (Anthropic `system`, as string or text blocks), then each message's `content` string or each of its `{"type": "text"}` blocks. One entry per text part, so one message with two text blocks gives two entries with the same role. Images, tool definitions and tool arguments are not sent. |

## Answer

Answer `200` with a JSON body:

```json
{
  "action": "mask",
  "reason": "payment card number",
  "findings": [ { "kind": "credit_card", "message": 1 } ],
  "masked_messages": [
    "You are a support assistant.",
    "My card is [CARD], why was it declined?"
  ]
}
```

| Field | Rules |
|---|---|
| `action` | Required. `allow`, `block` or `mask`. |
| `reason` | Optional. One line, at most 500 characters, no control characters. Checked, then neither shown to the caller nor recorded: it is free text that may quote the prompt, and refusals end up in client logs. Keep it for your own logs. |
| `findings` | Optional list. Each entry is `{"kind": "...", "message": <index>}`. `kind` is 1 to 64 letters, digits, `.`, `-` or `_`; it is written to the audit record, so it must never hold the matched text. `message` is optional, a 0-based index into the `messages` Gantry sent. |
| `masked_messages` | Required when `action` is `mask`, refused otherwise. Exactly one string per entry of `messages`, in the same order. Gantry writes each changed string back into the request at the place it came from; unchanged ones are left as they were. |

Unknown fields are refused, so a misspelled field fails loudly instead of being ignored.

What Gantry does with each answer (with the guardrail's `action: block`):

- `allow`: forwards the request. Any findings are recorded with audit action `warn`.
- `block`: refuses the request with error code `guardrail_blocked` (403, Anthropic type `permission_error`, `x-should-retry: false`) and the message `Guardrail "<name>" refused this request: the guardrail service found <kind> (<count>), ...`. Findings are recorded with action `block` (kind `unspecified` if there are none).
- `mask`: forwards the changed request. Findings are recorded with action `mask`.

A malformed answer is treated as a failure of the service, so `on_failure` applies. So is an answer with a status other than 2xx, no answer within `timeout_ms` (the timeout covers connecting, sending and reading the whole answer), or a service that cannot be reached. With `fail_closed` the caller gets `guardrail_blocked` with a message that says the guardrail could not check the request. Gantry logs the cause for the operator. Examples of the causes it names:

- `missing field 'action'`, `unknown variant 'deny', expected one of 'allow', 'block', 'mask'`, `unknown field 'score'`
- `the answer says mask and has no masked_messages`
- `masked_messages has 1 string and the request had 2 messages`
- `masked_messages is only read when action is mask`
- `a finding points at message 2, and the request had 2 messages`
- `a finding's kind must be 1 to 64 letters, digits, dots, dashes or underscores`

Example block answer:

```json
{ "action": "block", "reason": "prompt injection detected", "findings": [ { "kind": "prompt_injection", "message": 1 } ] }
```

## Audit

Gantry records one entry per guardrail and kind: `guardrail`, `detector` (`secrets`, `pii` or `webhook`), `kind`, `action` (`block`, `mask`, `warn`, or `skipped` when a `fail_open` service did not answer) and `count`. A service that could not be reached is recorded with kind `unavailable`. No matched text and no reason is ever recorded.

## Worked example: a vendor behind an adapter

A service that speaks this contract and takes a header credential needs no adapter: set `url` and `headers_env`. Most guardrail vendors have their own API shape. The pattern that connects one of those to Gantry is a small adapter on the same machine (or the same pod) that speaks this contract on one side and the vendor's API on the other. Gantry needs nothing vendor-specific, and the vendor key never enters the policy file.

The example below is vendor-neutral: "your guardrail vendor" stands for any of them. It is a pattern, not a description of any vendor's API: the adapter's job is to call whatever endpoint and format your deployment documents, and to map its verdict onto `allow`, `block` or `mask`.

```text
client -> Gantry --POST contract JSON--> adapter on 127.0.0.1:9100 --vendor API + vendor key--> vendor deployment
                 <--allow/block/mask----                          <--vendor verdict-----------
```

Policy file:

```yaml
guardrails:
  - name: vendor
    type: webhook
    url: http://127.0.0.1:9100/check   # the adapter; plain HTTP is accepted only on this machine
    timeout_ms: 800                    # the adapter's own call to the vendor must fit inside this
    on_failure: fail_closed            # nothing goes out unchecked while the vendor is down
    action: warn                       # start by recording only; switch to block once the findings look right
rules:
  - name: everyone
    principals: { any: true }
    models: ["*"]
    guardrails: [vendor]
```

What the adapter does with each call, in outline:

1. Read the contract JSON. Pass `messages` (role and text) to the vendor in its format, with `person`, `team` and `decision_id` as metadata if the vendor takes it, so its console and Gantry's audit log can be joined on `decision_id`.
2. Authenticate to the vendor with a key from its own environment or secret store. If the adapter itself wants a credential from Gantry, name it in `headers_env`.
3. Map the vendor's verdict: nothing found is `{"action": "allow"}`; a finding the company wants stopped is `{"action": "block", "findings": [{"kind": "<the vendor's category>"}]}`; a redaction is `{"action": "mask", "masked_messages": [...]}` with exactly one string per message received.
4. Never put the matched text in `kind`. Use the vendor's category name.
5. If the vendor errors or is slow, answer with a non-2xx status or not at all: Gantry then applies `on_failure`, which is what you want, rather than an `allow` that hides the outage.

To move the adapter or point it at another vendor, change `url` and save the policy file. The next request uses the new URL; no restart is needed.
