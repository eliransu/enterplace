# Security model

Gantry's job is to make sure no AI request leaves without a known person, a decision and a record. This page says what this version protects and where it stops.

## What is protected

**Fail closed.** A request that cannot be identified, decided and recorded is not forwarded. If the audit log cannot be written, every request is refused (`audit_unavailable`) and `/healthz` answers 503 until an admin restarts Gantry. Gantry does not start on an audit log whose chain does not hold, on a policy file with any problem, or without every provider key.

**Gantry keys.** 256 random bits from the operating system, prefixed `gantry_` so secret scanners recognize them. Shown once. Only the SHA-256 is stored, in a keys file created with mode `0600`. A lookup is by hash, so Gantry never compares secret bytes one at a time.

**Provider keys.** Read from environment variables, never from a file Gantry reads or writes. Held in memory marked as sensitive and never printed. Sent only to the provider that needs it, in that provider's header.

**What the provider sees.** The caller's Gantry key is removed from every header, under any name, compared without regard to case, with or without the `gantry_` prefix. Any header whose name contains `authorization`, `key`, `token`, `secret`, `organization` or `project` is dropped (except `idempotency-key`), so a caller cannot choose the provider account or project, and so is any header starting with `x-amz` (`x-amzn-*` included): AWS headers are Gantry's to sign and set. A body sent with a `Content-Encoding` other than `identity` is refused, so what the provider gets is what was checked. `Cookie` and `Host` are dropped.

**One credential, one model.** Two different credentials on one request are refused (`ambiguous_key`), so Gantry never checks one credential and forwards another. A body with a second spelling of the `model` key (such as `Model`) is refused, so the policy cannot check one model while the provider runs another.

**Nothing silently dropped.** Unknown keys in the policy file are errors. Query parameters a route does not allow are refused by name, never removed. The body is forwarded byte for byte.

**The audit chain.** Each record holds the hash of the one before. `gantry audit verify` finds a changed, inserted, removed or reordered record and says which. Records hold no prompt or answer text and no keys. Each names the SHA-256 of the policy and keys files that decided it.

**Guardrails.** A rule can name guardrails that read the text of every request it allows before the request is recorded and sent: built-in `secrets` and `pii` detectors, and `webhook` guardrails that ask an outside service. They block, mask or record what they find. The record, the refusal and Gantry's log name the guardrail, the kind of finding and where it was, never the matched text. A webhook's free-text `reason` is not shown or recorded either, because it may quote the prompt.

What guardrails catch, honestly:

- **Pattern detectors, not understanding.** `secrets` finds keys with a known shape (AWS access key IDs, GitHub, Slack, JWTs, `sk-` keys, Gantry keys, PEM private keys). A password, a database URL with credentials or a key with no known prefix is not found. `pii` finds email addresses, phone numbers, card numbers that pass Luhn, IBANs that pass mod 97, Israeli IDs that pass their check digit and US SSNs. A name, an address or a date of birth is not found; use a webhook service for those.
- **False positives.** Any 9-digit number with a valid Israeli ID check digit, and some long digit runs that pass Luhn, are reported. Start with `warn` to see what a rule would catch before you `block` or `mask`.
- **Only text parts are read.** The system prompt, every text message or text block, the text in tool results (so a chat `tool` message gets the same verdict on the native and the translated route), text documents (`document` with a `text` or `content` source), search results, and on `/v1/responses` a tool's output (`function_call_output`) and the variables of a stored `prompt`. Tool arguments, images and files (a PDF or any base64 document) are not read, so text placed there passes unchecked.
- **Stored Responses state is not read and is shared.** A Responses request that names `previous_response_id`, `conversation` or a stored `prompt` makes the provider add text Gantry never sees, so guardrails do not check it. Every person's stored responses sit under Gantry's one provider key, so anyone who learns another person's response ID (it is in the answer, and in a cached answer served to others) can continue that conversation through Gantry. Send `store: false` and the whole conversation in `input`, as Codex does; under a budget, such a request is refused unless the model's price sets `max_context` (see [Policy file](policy.html)).
- **Each key once.** On a rule with guardrails, a body that names the same key twice in any object is refused (`unreadable_request`): a guardrail would read one copy and a provider might act on the other.
- **Plain text only.** Anything encoded, split across messages, spelled out or translated is not found by the built-in detectors.
- **Answers are checked only when a guardrail asks.** A guardrail with `on: [answer]` reads whole answers. A streamed answer is passed on as it arrives and its record says `not_run`, unless the rule sets `buffer_stream: true`: then Gantry holds the stream whole, checks it and replays it, and the caller's first token waits for the model's last ([Guardrails](guardrails.html#checking-the-answer)).
- **A webhook is as strong as its `on_failure`.** `fail_open` forwards requests unchecked while the service is down, and records `skipped` for each.
- **Masking changes the bytes.** A masked request is re-serialized from its parsed JSON (key order and numbers are kept). A request with nothing masked is forwarded byte for byte.

**Console sign-in with single sign-on.** Besides an admin key, people can sign in to the console through an OpenID Connect identity provider (Okta, Microsoft Entra ID, Google, Keycloak and others). It is set in the policy file:

```yaml
console:
  sso:
    issuer: https://login.example.com          # exactly as the provider writes it
    client_id: gantry-console
    client_secret_env: GANTRY_SSO_SECRET       # the variable's name; the secret never goes in the file
    redirect_url: https://gantry.example.com/console/sso/callback
    allowed_domains: [example.com]             # and/or allowed_emails: [guest@partner.org]
    role_claim: groups                         # an ID token claim, a string or a list
    admin_values: [gantry-admins]              # may issue and revoke keys
    read_only_values: [gantry-viewers]         # may look, not change
```

Register `redirect_url` at the provider, set the secret's variable where Gantry runs, and make the provider put the email and the role claim in the ID token (Gantry does not call the userinfo endpoint). The sign-in page then shows "Sign in with single sign-on".

What Gantry checks, and refuses on any failure with a message that names the cause and the fix:

- The authorization code flow with PKCE (S256), a random `state` tied to the browser by a cookie and usable once within 10 minutes, and a `nonce`. Starting a sign-in keeps nothing on the server: the cookie holds the state and its expiry, sealed with an HMAC key made at each start of the process, and the nonce and PKCE verifier are derived from the state under that key. A flood of unauthenticated `/console/sso/start` requests therefore fills nothing and locks nobody out. Only finished sign-ins are remembered (at most 10,000, until their 10 minutes are up) to refuse a second use. A minute with 100 or more starts writes one `console_sso_starts` admin record, at most once a minute. Refused sign-ins are recorded one by one, up to 100 a minute from each client address (an IPv6 client counts by its /64), so a flood from one address hides nobody else's. Past that, the address's minute is summed up in one `console_sso_refusals` record written when the minute closes, with the true count and the count per refusal code.
- Discovery from `<issuer>/.well-known/openid-configuration`, whose `issuer` must equal the configured one. Its endpoints must be https (plain http only to localhost). Discovery and the key set are cached for 10 minutes; a token signed with a key not in the cache fetches them again once, so key rotation is followed.
- The ID token's signature, RS256 or ES256 only, with the key its `kid` names. Then `iss`, `aud` (and `azp` when there are several audiences), `exp` (60 seconds of clock difference allowed) and `nonce`.
- The `email` must be in `allowed_emails` or have a domain in `allowed_domains`, and must not be marked `email_verified: false`. The role claim must hold a value from `admin_values` (admin) or `read_only_values` (read only). There is no default role: anyone else is refused.

Every sign-in, refusal and sign-out is an `admin` record in the audit chain, with `action: console_sign_in` or `console_sign_out`, the email as `person`, `target.via: sso`, the role on a sign-in and the reason on a refusal (codes `sso_state`, `sso_provider`, `sso_issuer`, `sso_token`, `sso_signature`, `sso_unknown_key`, `sso_audience`, `sso_expired`, `sso_nonce`, `sso_email`, `sso_role`, `sso_config`, `sso_secret`). A read-only person who tries to issue or revoke a key is refused and recorded with code `read_only`. The policy file is read on every console page, so removing `console.sso` or a person's email or domain ends their session at once; a change of role at the provider applies at the next sign-in.

**Resource limits.** A caller who is not identified is refused before their body is read. Body size, memory per caller and in total, and every wait (headers, body, connect, first byte) are bounded. See [Operations](operations.html).

**Exposure.** Gantry binds `127.0.0.1` unless told otherwise and warns when it is not. `--unchecked` refuses to bind anything but loopback. Provider URLs on this machine or a private network are refused unless the provider says `allow_private: true`, which limits a policy file pointing Gantry at internal services by mistake.

**The container.** One static binary, no shell, no package manager, no other files. Runs as user 65532. The policy and keys are mounted read-only; only `/var/lib/gantry` is writable.

## Stated limits

These are known and not fixed in this version:

- **No TLS.** Gantry serves plain HTTP. Keys travel in the clear unless TLS sits in front of it. Keep it on loopback or behind a TLS proxy.
- **Records removed from the end** leave an unbroken chain. Keep the last hash elsewhere and compare. See [Audit log](audit.html).
- **Up to a second of records** can be lost on a power failure: they are synced to disk once a second.
- **The decision record is of the decision**, not of the provider's answer. A usage record (status, tokens, cost) follows each answer, and an attempts record each retried request, but a request that got no answer at all has neither: its `upstream_*` failure is not in the log.
- **Private addresses are judged by what is written.** A public host name that resolves to a private address is not caught.
- **The key search is a text match.** A Gantry key split across headers or encoded is not found and removed. Such a header would still have to pass the name filter above.
- **A removed key works for up to 2 seconds** after the keys file is saved, until the reload picks the change up. Revoking through the console or the admin API stops it at once.
- **One node.** No shared state, no high availability. Console sessions and sign-ins in progress live in memory: a restart signs everyone out, and behind a load balancer the provider's callback must reach the node that started the sign-in.
- **A request the HTTP library rejects** as malformed gets a bare 400 with no decision ID and no record.
- **`client` in the record** is the address of the connection, so behind a proxy it is the proxy.
- **Anyone who can write the keys file or policy file** decides who may do what. Protect them like the provider keys.
- **Anyone who can write the audit log file** can rewrite the whole chain consistently. The last hash kept elsewhere is what catches that.

**`gantry login`.** The browser never carries a key: it brings a one-use code (two minutes) back to a listener on `127.0.0.1` whose port, state and PKCE challenge are sealed in a cookie bound to that one sign-in, and only the CLI holding the PKCE verifier can trade the code for the key. A console sign-in clears what an abandoned `gantry login` left. Self-issue needs its own `console.sso.self_issue` allow list and gives a key that expires (30 days unless set). The CLI sends a key only to an https address (plain http only to this machine) and keeps it in a file only its owner can read.

**Kill switches** are in force on the node that sets them before it answers and on every node serving the same files within 1 second. A switch file that cannot be read when it changes, or at start, refuses every request, fail closed; a file made unreadable without changing its size or time keeps the last list it read in force until the next change or restart. Two nodes changing switches at the same instant can lose one change.

**Not built yet (planned):** SAML sign-in, SCIM provisioning, roles finer than admin and read only, and budgets and rate limits shared by more than one node. TLS in Gantry itself is built: `gantry serve --tls-cert --tls-key`, and console cookies are then marked `Secure`.

## Reporting a problem

Report a security problem privately to the maintainers, not in a public issue. A security contact is not published yet.
