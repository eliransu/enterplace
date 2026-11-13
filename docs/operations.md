# Operations

## Health check

```text
GET /healthz
```

- `200 ok`: Gantry can do its job.
- `503 the audit log cannot be written`: a write failed, or the log file was deleted, moved, replaced or cut short. Every request is refused until restart, so a load balancer should stop sending traffic. After a full disk, free the space; if the start then says the last line is cut short, run `gantry audit repair <file>` to see that line and `gantry audit repair <file> --yes` to remove it with a record of the repair ([Audit log](audit.html#a-last-line-cut-short)).

The health check needs no key and is not recorded.

## Start-up

`gantry serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>] [--tls-cert <pem> --tls-key <pem>]`:

1. Reads and checks the policy and keys files (the same check as `gantry check`). Any problem stops the start.
2. Reads every provider key from its `key_env` variable. A missing or empty one stops the start.
3. Opens the audit log and verifies the whole chain. A log that does not hold stops the start.
4. With `--tls-cert` and `--tls-key`, reads the certificate and key. A missing file, or a key that does not match the certificate, stops the start.
5. Binds the address, then prints `listening`. With `--metrics`, binds that address too and serves `GET /metrics` there: [Metrics and log shipping](observability.html).

It warns when the keys file has no keys (every request would be refused) and when the address is not loopback and TLS is off (keys travel over plain HTTP).

A change to the policy or keys file is used within 2 seconds without a restart (see the README, "Changing the policy and keys"). Rotating a provider key, the audit log path and a provider's name, kind, url, key_env, allow_private, region or api_version take a restart. `SIGTERM` or Ctrl-C stops accepting connections and gives requests in flight 30 seconds to finish; a second signal ends the wait. Before the process ends, every record already handed to the audit writer is written and synced, including the usage record of an answer that ended just before the stop. A new audit log is created with mode `0600`.

## Limits

Fixed in this version, not configurable:

| Limit | Value | What happens |
|---|---|---|
| Request body | 32 MiB | `body_too_large`, 413 |
| Request bodies held in memory, all callers | 256 MiB | `busy`, 503, `Retry-After: 1` |
| Request bodies held in memory, one caller (person or workload) | 64 MiB | `busy`, 429, `Retry-After: 1` |
| Audit strings from the caller | 200 characters | cut |

Memory for a body is reserved as its bytes arrive, never ahead of them, and nobody waits in a queue for it: a large request cannot hold small ones up. The memory is released once the request has been handed to the provider. Answers stream through and are not buffered.

Budgets, rate limits and the cache are per rule: see [Policy](policy.html#budgets). Their counts live in the memory of one Gantry process; budgets are read back from the audit log at start, rate-limit windows and the cache start empty. Answers stream through unbuffered. The pieces of a whole (not streamed) answer are kept by reference as they pass, up to 32 MiB, to read its usage and, under a cache, to keep it; the usage is read and the usage record written on the audit writer's thread, not on the answer's path.

A key can carry a budget of its own (`budget:` on its entry, or `gantry key new --budget 20/month`), counted apart from its rule's and refused with `key_budget_exceeded`: [Keys](keys.html).

**Not built yet (planned):** budgets shared by more than one node.

## Timeouts

| Wait | Default | On expiry |
|---|---|---|
| Client sends its request headers | 10 s | connection closed |
| Client sends its request body | 30 s | `body_timeout`, 408 |
| TCP connect to the provider | 5 s | `upstream_unreachable`, 502 |
| Provider starts answering (first byte) | 120 s | `upstream_timeout`, 504 |
| Requests in flight after a stop signal | 30 s | process exits |

There is no limit on how long a streamed answer runs once it has started. Gantry serves HTTP/1.1 only.

## Memory budget

What the process uses is small and mostly the request bodies in flight:

- Idle: about 3.4 MiB in the container and 4.9 MB resident on macOS, measured on 2026-11-13 with a two-provider policy and two keys.
- Bodies: at most 256 MiB across all callers, by the limits above.
- Keys and rules: held in memory, a few hundred bytes per key.
- Per caller: one small entry per person or workload that has sent a request, kept until restart.

A container memory limit of 384 MiB leaves room for the full body budget. Measure under your own load before setting it lower.

## Audit log on disk

Records reach the operating system before forwarding and are synced to disk once a second. A decision record is about 650 bytes and a usage record about 700 (measured on 2026-11-13), so a million forwarded requests make about 1.35 GB. Gantry reads the whole file at every start to verify it; the time this takes grows with the file. Rotation is not built: to start a new chain, stop Gantry, move the file aside (keep it, with its last hash), and start again.

## Bench

```bash
cargo run --release -p gantry-bench -- --rps 1000 --secs 10 --max-p99-overhead-us 1000
```

The bench runs a mock model server and the gateway in one process, sends the same open-loop load to each, and prints what the gateway adds as the client sees it, plus the time Gantry reports for identifying, deciding and recording (`Server-Timing: gantry;dur=`). With the policy on (the default: 1,000 keys, and a `secrets` guardrail that blocks on every rule) it also fails unless the audit log holds exactly one decision record and one usage record per request, in an unbroken chain. Options: `--stream` for streamed answers, `--messages` for `/v1/messages`, `--no-policy` to measure forwarding alone, `--max-p99-overhead-us N` to exit 1 when added p99 latency is above N microseconds.

Writing the record before forwarding costs about 70 to 100 microseconds per request on a laptop, most of it waiting for the writer thread to wake. CI gates at 1,000 microseconds added at p99, at 1,000 requests a second. The numbers compare builds on one machine; they are not a published benchmark.

How `scripts/ci.sh` runs the gate: a 2-second warm-up (not judged), then up to three 5-second attempts, each printed in full and preceded by the output of `uptime`, so the machine's load average sits beside every result. The gate passes as soon as one attempt passes, and fails only if all three do. The limit is the same 1,000 microseconds: a real regression adds latency to every attempt and still fails, while a laptop or a shared CI runner busy with something else for a few seconds no longer turns the build red. When all three fail, read the load averages first: the bench also refuses on its own, naming the cause, when the mock upstream alone is slow ("the machine is too busy"). `scripts/ci.sh --no-bench` skips the gate on a machine that cannot time anything.

## TLS

### Gantry serves HTTPS itself

```bash
gantry serve gantry.policy.yaml --listen 0.0.0.0:8443 --tls-cert /etc/gantry/tls/tls.crt --tls-key /etc/gantry/tls/tls.key
```

Both flags or neither. The certificate file is PEM, the server certificate first and then any intermediates; the key is the matching unencrypted PEM private key (PKCS#8, PKCS#1 or SEC1). TLS 1.2 and 1.3, through rustls. A plain HTTP request to that port gets no answer. The files are read once at start: to use a renewed certificate, restart Gantry. Gantry still serves HTTP/1.1 only, over TLS too. The console marks its cookie `Secure` only when it sees `X-Forwarded-Proto: https`, so with Gantry's own TLS and no proxy the cookie is sent without that flag (it is still `HttpOnly` and `SameSite`).

A certificate for a test, made with openssl (the files under `crates/gantry-server/tests/tls` were made this way, with a test CA signing the leaf):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem -days 30 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
```

### A proxy in front

Or keep Gantry on loopback or a private network and put a proxy that ends TLS in front of it. The proxy must stream answers (no buffering) and send `X-Forwarded-Proto: https`, which the console needs to mark its cookie `Secure`. Gantry records the address of the connection it sees, which is the proxy's.

Caddy (gets and renews its own certificate):

```text
gantry.example.com {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

nginx:

```text
server {
    listen 443 ssl;
    server_name gantry.example.com;
    ssl_certificate     /etc/ssl/gantry.pem;
    ssl_certificate_key /etc/ssl/gantry.key;
    client_max_body_size 32m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 600s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Caddy sets `X-Forwarded-Proto` by itself. Both examples follow each tool's documented directives and were not run in this release.

## Stop everything at once

```sh
gantry kill --all --reason "provider incident, stopping all AI traffic"
gantry unkill --all
```

`gantry kill --all` refuses every request with `killed` within 1 second on every node serving the same files, and the people stopped see the reason; the admin API stays open so an admin can turn it off. The same command takes `--person`, `--team`, `--key-prefix` or `--model` to stop less. See [Keys](keys.html#kill-switches). To stop one person for good, revoke their key in the console or with `DELETE /admin/keys/<prefix>`.

## Unchecked mode

`gantry serve --unchecked` forwards `POST /v1/chat/completions` without identity, policy or audit, on a loopback address only. It exists for benchmarks. `GANTRY_ADDR` sets the address (default `127.0.0.1:8080`) and `GANTRY_UPSTREAM` the server to forward to. It refuses to start on an address other machines can reach.

## Release builds

| Command | Output |
|---|---|
| `scripts/release.sh tarball` | `dist/gantry-<version>-<src>-<host target>.tar.gz` with its `.sha256` and `.BUILD` (the `gantry version` line), for the machine you are on. `<src>` is the source hash `gantry version` prints. Earlier tarballs of that target are deleted first |
| `scripts/release.sh image` | image `gantry:<version>` and `gantry:local` for this machine's platform |
| `scripts/release.sh images` | image for `linux/amd64` and `linux/arm64` (needs `docker buildx`) |
| `scripts/release.sh linux` | `dist/` tarballs for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, named and cleared the same way |
| `scripts/release.sh smoke` | runs the image against a local mock: passes when it is under 50 MB, non-root, prints the same `gantry version` line as `target/release/gantry` (when that exists), and answers a governed request within 60 seconds of `docker run` |

`scripts/ci.sh` runs every check CI runs (`.github/workflows/ci.yml`). The workflow is defined but has not run on a hosted service yet, because nothing is committed.

Nothing is published to a registry yet.
