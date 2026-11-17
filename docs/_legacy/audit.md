# Audit log

Every request Enterplace decides leaves one line in the audit log, allowed or refused, written before anything is forwarded. A request that cannot be recorded is refused with `audit_unavailable` and never reaches a provider. Each forwarded request gets a second line, its [usage record](#usage-records), when its answer ends.

The log is a file of JSON lines, by default `enterplace-audit.jsonl` beside the policy file, or the path in `audit: { path: ... }`.

## A record

```json
{"n":1,"id":"01M7969SBMMKV7S7HFP6Q99SPJ","time":"2026-11-13T00:53:10.132Z","person":"maya.cohen","team":"payments","client":"127.0.0.1","key":"5d1e4a07","method":"POST","path":"/v1/chat/completions","model":"gpt-oss:20b","verdict":"allow","code":null,"rule":"payments-team","rule_line":16,"provider":"local","policy_sha256":"6d0782...","keys_sha256":"37b02a...","prev":"0000000000000000000000000000000000000000000000000000000000000000","hash":"84347ac2..."}
```

| Field | Meaning |
|---|---|
| `n` | Record number, from 1, one more than the record before. |
| `id` | The decision ID: 26 characters, sortable by time (ULID layout). The same ID is in the `X-Enterplace-Decision` header and in every refusal message. |
| `time` | UTC, millisecond precision, when the record was made. |
| `person` | The name the key was issued to, or `"unknown"` when the caller was not identified. |
| `team` | The key's team, or `null`. |
| `client` | The IP address the connection came from. Behind a proxy this is the proxy. |
| `key` | The first 8 hex characters of the SHA-256 of the key the request came with, issued or not: tells two keys of one person apart during a rotation, and unknown keys apart. `null` when the request carried no key. Usage records carry it too, and per-key budgets are counted from it. Never the key. |
| `method`, `path` | As the request came, without the query. |
| `model` | The `model` field of the body, or `null` if the request was refused before the body was read. |
| `verdict` | `allow` or `refused`. |
| `code` | The refusal code, or `null`. See [Refusal codes](refusals.html). |
| `rule`, `rule_line` | The rule that decided and its line in the policy file, or `null` when no rule applied. |
| `provider` | The provider the request was sent to, or `null` if refused before one was chosen. |
| `policy_sha256`, `keys_sha256` | SHA-256 of the policy file and keys file as loaded, so a record shows which version decided it. |
| `cache` | Only for a rule with a [cache](policy.html#cache): `hit` when the answer came from the cache and never reached the provider, `miss` when it could have and did not. |
| `translated` | Only when a chat request was translated for a provider with `accept_chat`: `true`. |
| `alias`, `deployment` | Only for a request to an [alias](providers.html#aliases-and-load-balancing): the alias the caller sent, and the deployment tried first as `provider/model`. |
| `limit` | Only on a refusal by a limit, saying which one: `{"kind": "rpm", "of": "rule", "value": 60}`, `{"kind": "tpm", "of": "rule" or "key", "value": 1000, "request_could_use": 1228}`. |
| `key_models` | Only on a `model_not_allowed` refusal by the key's own `models:` list (the rule allowed the model): `true`. |
| `guardrails` | Only for a rule with guardrails: one entry per guardrail and kind found (`guardrail`, `detector`, `kind`, `action`, `count`). An empty list means they ran and found nothing. Never the matched text. See [Guardrails](policy.html#guardrails). |
| `prev` | The `hash` of the record before, or 64 zeros for record 1. |
| `hash` | SHA-256 of this line's text up to `prev` and its value, closed with `}`. |

Strings that come from the caller (model, path) are cut to 200 characters, so a caller cannot choose the size of a record.

A record never holds prompt text, answer text, a Enterplace key or a provider key. It says what Enterplace decided, not how the provider answered. How the provider answered is in the usage record that follows it; a request that got no answer at all (an `upstream_*` failure) has none.

Other kinds of record share the chain, each with an `event` field: `config_loaded` and `config_rejected` when the policy or keys file changes (see the README), `admin` for each call to the admin API and each console sign-in, sign-out, issue and revoke (its `action` is one of `list_keys`, `issue_key`, `revoke_key`, `revoke_own_key`, `self_issue_key`, `list_kills`, `set_kill`, `clear_kill` and the console's own; its `key` is the caller's key hash prefix), `attempts`, which follows a request record with the same `id` when the request was tried more than once (see [Providers](providers.html#retries-and-fallbacks)), and `answer_guardrails`, which follows a request record with the same `id` when its rule has guardrails with `on: [answer]`: its `verdict` is `block`, `mask`, `pass` or `not_run` (a streamed answer on a rule without `buffer_stream`), and `guardrails` lists what each found, never the text (see [Guardrails](guardrails.html#checking-the-answer)).

## Usage records

When a forwarded request's answer ends (its whole body sent, its stream finished, or the caller gone), Enterplace writes what it used and cost. The answer is passed on as it comes, and no byte waits for its usage. A stream's usage is read from its events as they pass. A whole answer's pieces are kept by reference as they pass, and its usage is read when it ends. The usage record is made and written on the audit writer's thread, in turn with the other records. Usage is read from the provider's own answer: before it is translated for a chat client, and after a Bedrock stream is decoded. When a request fell back to another provider, `provider` names the one that answered.

```json
{"n":2,"event":"usage","id":"01M7969SBMMKV7S7HFP6Q99SPJ","time":"2026-11-13T00:53:11.020Z","person":"maya.cohen","team":"payments","model":"claude-sonnet-5-5","provider":"anthropic","status":200,"ended":"complete","usage":"reported","input_tokens":100,"output_tokens":20,"cache_read_tokens":1000,"cache_write_tokens":0,"price":"known","price_source":"builtin","cost_usd":0.0004,"reserved_usd":0.0412,"charged_usd":0.0004,"policy_sha256":"6d0782...","keys_sha256":"37b02a...","prev":"...","hash":"..."}
```

| Field | Meaning |
|---|---|
| `event` | `usage`. |
| `id` | The decision ID of the request, as on its decision record. |
| `person`, `team`, `model`, `provider` | As decided. |
| `status` | The provider's HTTP status. |
| `ended` | `complete`, or `cut_off` when the caller went before the answer ended (or before it started). |
| `usage` | `reported`, `partial` (cut off before the event that carries the final counts: the tokens are only what was generated before the cut), `estimated` (a stream without a budget that the provider finished without usage, as an OpenAI stream without `stream_options.include_usage`: charged from its streamed text, see [Policy file](policy.html); under a budget such a stream is `not_reported` and charged its reservation), `not_reported` (any other answer without usage, or an error), `caller_left` (the caller hung up after the request was forwarded and before the answer started: no counts, `status` null, charged the reservation or, without a budget, the estimate of the most it could cost, and counted in full against tokens per minute), or `cache_hit`. |
| `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens` | As the provider reported them. Input excludes cache reads and writes. `null` when not reported; 0 for a cache hit. |
| `price` | `known`, or `none` for a model with no price. |
| `price_source` | Where the price came from: `policy` (the policy's `prices:`), `builtin` (Enterplace's own table), `litellm` (the table generated from LiteLLM's price map), or `null` with no price. `enterplace prices <model>` shows the same. |
| `cost_usd` | What the answer cost at the model's [price](policy.html#prices). `null` when the usage or the price is unknown: never a guess. 0 for a cache hit. |
| `reserved_usd` | What the request reserved against its [budget](policy.html#budgets), or `null` without one. |
| `charged_usd` | What counts against budgets. For a 2xx answer: `cost_usd` when it is whole; the larger of `cost_usd` and the reservation when `usage` is `partial`; the reservation when no usage was reported (without a budget, the same estimate of the most the request could cost). Otherwise `cost_usd`, or 0. At start, Enterplace sums this field over the current month. |
| `policy_sha256`, `keys_sha256` | The version that decided the request. |

A request that never got an answer (an `upstream_*` failure) has no usage record, and its reservation is given back. `enterplace audit verify` counts usage records apart from requests, and attempts records when there are any.

Not recorded: `GET /healthz`, `HEAD /api/hello` (Claude Code's startup probe; other methods on both paths are refused and recorded), and a request so malformed that the HTTP library rejects it before Enterplace sees it (that one gets a bare 400 with no decision ID).

## Durability

The record reaches the operating system before the request is forwarded. Enterplace asks the system to put the file on disk once a second, so a power loss can lose up to about a second of records that were already acted on. A process crash loses none.

If a write fails, or the file is deleted, moved, replaced or cut shorter while Enterplace runs, every later request is refused with `audit_unavailable`, `GET /healthz` answers 503, and the server log says what happened. Enterplace does not write to that file again until it is restarted.

### A last line cut short

A write that fails part way (a full disk) can leave the last line cut short, and `enterplace serve` then refuses to start, naming the command to run. Free the space, stop Enterplace, and run:

```
enterplace audit repair enterplace-audit.jsonl
```

It checks that the chain holds up to the cut line, prints that line and changes nothing (exit 1). Then:

```
enterplace audit repair enterplace-audit.jsonl --yes
```

removes only that line and appends an `audit_repaired` record holding what was removed (`removed_bytes`, `removed_sha256`, `removed_text`), so the repair is itself in the chain. It removes nothing else: a changed or missing record anywhere, or a whole last line that is not a record, is reported as `enterplace audit verify` reports it, with the record where the chain breaks, and `audit repair` exits 1 and leaves the file as it is, also when the last line is whole (a log changed in the middle is evidence, not something to repair). `enterplace audit verify` on a log whose only fault is a cut last line points at `enterplace audit repair`. `enterplace audit verify` counts `audit_repaired` records with the admin records.

Repair offers a last line for removal only when it is the start of the next record cut short: it does not parse as JSON and begins as that record must (`{"n":<next number>,`, or a shorter piece of it). A last line that is whole JSON without its newline (a record that lost its newline, or a changed one) and a last line that is anything else are refused and left in place, so a changed record is never turned into a repair. While a Enterplace process has the log open it keeps a lock file beside it (`enterplace-audit.jsonl.lock`, holding its process ID), and `audit repair --yes` refuses while that file exists. A second `enterplace serve` on the same log refuses to start while the process the file names is running, and names the file; a Enterplace only removes a lock file that still holds its own process ID. A Enterplace stopped by a signal it could not handle (`kill -9`, a crash) leaves the file behind: the next `enterplace serve` takes it over once the process it names is gone, and for a repair, once Enterplace is surely stopped, delete it and run the repair again. Two containers that share one audit folder both run as process 1 and cannot tell each other apart: give each its own audit path. Repair also refuses if the file grows between the check and the removal.

The removed line's request is not counted again: when it was a usage record, its charge is gone from budgets after the restart (its text is kept in the `audit_repaired` record, `removed_text`).

## Verify

```bash
enterplace audit verify enterplace-audit.jsonl
```

```text
enterplace-audit.jsonl: 9 records in an unbroken chain from record 1 to record 9.
5 requests, 1 configuration record, 0 admin records, 3 usage records.
Last hash: 1ae338b73793e850d4a1a345e1648c1addde566b34dc70b1688fe50a887f7fb1
Records removed from the end leave the chain unbroken. To rule that out, compare this count and hash with a copy kept somewhere else.
```

`verify` walks the whole file and checks each record's hash and its link to the one before. A changed, inserted, removed or reordered record breaks the chain at that record:

```text
error: record 5 in enterplace-audit.jsonl does not hold: <what>. Records 1 to 4 are intact. Record 5 and everything after it cannot be trusted.
```

It exits with 0 when the chain holds and 1 when it does not. `enterplace serve` runs the same check on the whole file at every start and refuses to start on a log that does not hold:

```text
error: ... Enterplace does not start on an audit log that does not hold. Move the file aside to keep it, and start again to begin a new chain.
```

If only the last line is cut short (the process was stopped in the middle of a write), remove that line and start again.

## Keep the last hash

A chain cannot show records removed from its end: the shorter file is still an unbroken chain. To catch that, keep the count and last hash somewhere Enterplace's host cannot change, and compare:

```bash
enterplace audit verify /var/lib/enterplace/enterplace-audit.jsonl | sed -n 's/^Last hash: //p'
```

For example, a cron job that sends the count and last hash every hour to a log store or a ticket that the Enterplace host has no write access to. A later `verify` must show a count at least as high and, at that count, the same hash (`sed -n '<count>p' enterplace-audit.jsonl` shows that record).

**Not built yet (planned):** export to a SIEM, retention and legal hold (in the commercial product), and a checkpoint so start-up does not read the whole file.
