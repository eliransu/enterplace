# Keys

An Enterplace key identifies one person or one workload. Callers send it in place of a provider key; the provider keys stay with Enterplace.

## Make a key

```bash
enterplace key new maya.cohen --team payments [--keys enterplace.keys.yaml] [--url https://enterplace.example.com]
```

```text
Key for maya.cohen, team payments. It is shown once and is not stored anywhere:

  enterplace_3f9c...(64 hex characters)

To hand it over, send these lines through your secret manager, never in chat. Claude Code and the OpenAI SDKs read them:

export ANTHROPIC_BASE_URL=https://enterplace.example.com
export ANTHROPIC_API_KEY=enterplace_3f9c...
export OPENAI_BASE_URL=https://enterplace.example.com/v1
export OPENAI_API_KEY=enterplace_3f9c...

Its hash was added to /srv/enterplace/enterplace.keys.yaml. A running `enterplace serve` accepts it within 2 seconds. `enterplace serve` reads the keys file beside its policy file unless `--keys` names another.
```

The block is ready to paste into a shell profile, a `.env` file or a secret manager entry. Claude Code reads the two `ANTHROPIC_` lines; the OpenAI Python and Node SDKs, and tools built on them, read the two `OPENAI_` lines. `--url` is the address people reach Enterplace at (default `http://127.0.0.1:8080`). `--quiet` prints the key alone, for a pipe into a secret manager: `enterplace key new ci.bot --team platform --quiet | vault kv put secret/enterplace key=-`.

### The first admin

```bash
enterplace key new noa.bar --team platform --admin
```

An admin key may sign in to the console at `/console` and call the admin API to issue and revoke keys, including more admin keys. The first one is made this way on the machine that holds the keys file; nobody needs to edit `admin: true` by hand. After that, admins issue keys from the console or the admin API, or people sign in to the console through single sign-on ([Security model](security.html)).

### Expiry and budget per key

```bash
enterplace key new ci.release --team platform --expires 2026-12-31 --budget 20/month
```

- `--expires` takes a UTC date (`2026-12-31`: the key stops working when that day starts) or a UTC time (`2026-12-31T18:00:00Z`). An expired key is refused with `key_expired` (401), and the record names whose key it was.
- `--budget <usd>/<day|month>` caps what this key alone may spend, counted the same way as a rule's budget (reserved at admission, settled from the usage record, read back from the audit log at start) and on top of it. Over it, a request is refused with `key_budget_exceeded` (429, not retried). Use it for a CI job or an agent that shares a team with people.
- Both are written to the key's entry and can be changed by editing it: the change applies within 2 seconds, no restart.
- The admin API takes them too: `POST /admin/keys` with `"expires": "2026-12-31"` and `"budget": {"usd": 20, "per": "month"}`.

### Models and tokens per minute per key

```bash
enterplace key new ci.agent --team platform --models gpt-4o-mini,o3 --tpm 200000
```

- `--models` narrows what the key's rule allows to the models listed, for this key only; it never widens the rule. The admin API takes `"models": ["gpt-4o-mini", "o3"]` and refuses a model the policy does not serve.
- `--tpm` caps the tokens (prompt and answer) this key may use per minute, on top of its rule's limit. The admin API takes `"tpm": 200000`.
- Both are written to the key's entry (`models: [...]`, `tpm: N`) and work as described in [Policy file](policy.html#rate-limits).

### List keys

```bash
enterplace key list [--keys enterplace.keys.yaml]
```

```text
name	team	key	admin	expires	budget	models	tpm
noa.bar	platform	9b74c1d2	admin	-	-	-	-
ci.release	platform	41e0a7f3	-	2026-12-31	$20.00 a month	-	-
ci.agent	platform	7c2e90aa	-	-	-	gpt-4o-mini,o3	200000
```

It reads the keys file, never a key. The console's People page shows the same, with each key's last request.

- A key is `enterplace_` followed by 256 random bits in hex, from the operating system's random source. If the system gives no randomness, no key is made.
- The prefix lets a secret scanner recognize a leaked key.
- Only the SHA-256 of the key is written. The key itself is not kept anywhere.
- `--keys` defaults to `enterplace.keys.yaml` in the current directory. Note that `enterplace serve` looks for it beside the policy file, so run `key new` in that folder or pass the same path to both.
- Names and teams use letters, digits, `.`, `-`, `_` and `@`.

The keys file looks like this:

```yaml
# Keys Enterplace accepts. Only the SHA-256 of each key is kept here. Add keys with `enterplace key new`.
keys:
  - name: maya.cohen
    team: payments
    sha256: 5d1e...
  - name: ci.release
    team: platform
    sha256: 41e0...
    expires: 2026-12-31
    budget: { usd: 20, per: month }
```

It is created with mode `0600`. `key new` adds its entry to the end and never rewrites what is there, and it shows the key only after finding the entry in the file. If an editor saves the file at the same moment from an older copy, `key new` says so and makes no key; run it again. A run that retries after its own entry went in looks for that entry first and shows the key; if it cannot show the key, it takes its entry out again, or names the entry to remove. It extends a list indented by any depth, and `keys: []` with any spacing; a list written on one line (`keys: [...]`) is refused with that cause. A keys file that is a link to a missing file is refused as such.

## Send a key

A client sends the key in either place:

```text
Authorization: Bearer enterplace_...
x-api-key: enterplace_...
```

Both may be present only if they hold the same value. Two different credentials are refused with `ambiguous_key`. A value that starts with `sk-` and identifies nobody is refused with `unknown_key` and a hint that it looks like a provider key.

Enterplace removes the key from every header before forwarding, under any header name, compared without regard to case, with or without the `enterplace_` prefix.

## Rotate a key

1. Run `enterplace key new` again with the same name and team. It says the name already had a key: `maya.cohen already had a key. Both work until you remove the old entry from the file.`
2. Within 2 seconds both keys work. No restart is needed.
3. Give the new key to the person or workload and wait until they use it. Every record names the key it came with by the first 8 hex characters of its hash (`key`), so the audit log shows when the old key stops being used.
4. Delete the old entry (the one with the older `sha256`, which is the one higher in the file) and save. Enterplace stops accepting it within 2 seconds.

## Remove a key

Delete its lines from `enterplace.keys.yaml` and save, or revoke it in the console or with `DELETE /admin/keys/<first 8 hex of the hash>`. Within 2 seconds (at once through the admin API, which reloads the keys file before it answers; the console saves the file and the change is used within 2 seconds, as its message says) a request with that key is refused with `unknown_key`, and the record holds the first 8 hex characters of the key's hash, enough to tell two unknown keys apart and far too little to recover the key.

`key new` never brings back an entry you removed by hand, even if it runs while you are editing.

## Rolling out to a team

1. Make the first admin key with `--admin`, on the machine that holds the keys file.
2. Issue each person's key with the admin API in a loop, or `enterplace key new <name> --team <team> --quiet` per person, and put each key straight into your secret manager or device management, never into chat or email.
3. Give each workload (CI job, agent) its own key with `--expires` and `--budget`.
4. Rotate by issuing a new key under the same name, then revoking the old one once the audit log shows it unused.

## Developers get their own key: enterplace login

With the console's single sign-on set up (see [Security](security.html)), a developer gets a personal key without an admin:

```bash
enterplace login https://enterplace.example.com
```

It opens the browser at the console, the person signs in at the identity provider, and the browser comes back to a listener the CLI opened on `127.0.0.1`. That redirect carries a one-use code, never the key; the CLI trades the code for the key together with a PKCE verifier only it holds (the code works once, for two minutes). The key:

- is named by the person's email and put in the team the policy says,
- expires after `expires_days` (30 unless the policy says otherwise),
- is recorded as an `admin` record with `action: self_issue_key`, the email as `person`, and the key's hash prefix and expiry in `target`.

The CLI saves it in `~/.config/enterplace/credentials` (`$XDG_CONFIG_HOME/enterplace/credentials` when set), readable by its owner only in a folder only they can open. Beside it, in `env` (also owner only), it writes the variables for Claude Code, the OpenAI SDKs and Codex (`ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `ENTERPLACE_KEY`), and prints the one line to add to a shell profile: `. ~/.config/enterplace/env`. Logging in again gives up the previous key and rewrites that file, so a profile that reads it keeps working; a profile holding the key itself would break at the next login. When a login key expires, or was replaced or revoked, the refusal (`key_expired` or `unknown_key`) says to run `enterplace login` again. `--no-browser` prints the address to open instead of opening it.

Who may self-issue is decided in the policy file, under `console.sso`:

<!-- not checked -->
```yaml
console:
  sso:
    # issuer, client_id and the rest as for console sign-in
    self_issue:
      allowed_domains: [example.com]   # or allowed_emails: [dana@partner.org]
      team: developers                 # default developers
      expires_days: 30                 # 1 to 365, default 30
```

No `self_issue` section, no `enterplace login`. No console role is needed: the key is for the person's own requests, which the policy's rules decide. An email outside the lists, or not verified, is refused and recorded (code `sso_self_issue` or `sso_email`), and the CLI prints why.

`enterplace logout` revokes the saved key through the admin API with the key itself (`DELETE /admin/keys/self`, which any key may call for itself, recorded as `revoke_own_key`), then deletes the credentials file and the `env` file. A key Enterplace no longer knows is taken as already revoked; within 5 seconds of `enterplace login`, when the new key may not be loaded yet, logout asks again for up to 3 seconds first.

Login keys that expire stay in the keys file. Serving refuses them (`key_expired`, recorded), and `enterplace check` lists each one as a warning, not a failure, so a check in CI keeps passing. `enterplace key prune` removes every expired entry, each with the same safe rewrite as `DELETE /admin/keys`, and keeps every other line:

```bash
enterplace key prune --keys enterplace.keys.yaml
```

## Kill switches

An admin stops traffic at once, with a reason the people stopped see in their tool:

```bash
export ENTERPLACE_URL=https://enterplace.example.com ENTERPLACE_ADMIN_KEY=enterplace_...
enterplace kill --person maya.cohen@example.com --reason "retrying the same ticket in a loop"
enterplace kill --team support --reason "support budget review"
enterplace kill --key-prefix 3f9a1c2e --reason "key pasted in a public issue"
enterplace kill --model gpt-4o --reason "provider incident"
enterplace kill --all --reason "suspected key leak, investigating"
enterplace unkill --person maya.cohen@example.com
```

A switch matches the name on the key (keys from `enterplace login` are named by email), the team on the key, the start of a key's hash, or the model the caller sent. A switch on a model also stops every alias with a deployment of that model (the whole alias, not only that deployment), and an alias's named fallback (`context_window_fallback`, `content_policy_fallback`) is not taken when a switch stops it by its name or the model of any of its deployments: the caller gets the deployment's own refusal. A switch that would match no key, team or served model is refused with `kill_matches_nothing` and the names it may have meant ("Keys named like it: maya.cohen@example.com"); `--force` (`"force": true` in the API) sets it anyway, for a key about to be issued.

A request a switch stops is refused with `killed` (403), whose message names the switch, the reason, who set it and when. Admin API calls are never stopped, so a switch on everyone can be turned off again. That holds for an admin a switch names too: a leaked admin key is stopped by revoking it, not by a switch. The switches are kept in memory and in `enterplace.kills.json` beside the keys file, so a restart keeps them; the node that takes the change applies it before it answers, and every other node serving the same files reads it within 1 second. Every set and clear is an `admin` record (`set_kill` with the reason, `clear_kill`). The API: `GET /admin/kills`, `POST /admin/kills` with `{"scope": "person", "value": "maya.cohen", "reason": "..."}` (scope `person`, `team`, `key_prefix`, `model` or `all`), and `DELETE /admin/kills` with the scope and value. While a switch is on, the console's Audit log shows a banner, and the record of a request it stopped names it.

A `enterplace.kills.json` that cannot be read refuses every request with `kills_unreadable` until it is fixed or deleted: Enterplace cannot tell who is not stopped.
