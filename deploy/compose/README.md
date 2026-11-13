# Gantry with Docker Compose

One machine: the Gantry gateway and Postgres 16, each with a named volume (`gantry-data` for the audit log,
`postgres-data` for the database). Keys, kill switches and budgets live in Postgres through the policy's `store:`
section. The policy is `gantry.policy.yaml` in this folder, mounted read-only; edit it and Gantry uses the change
within 2 seconds.

## From nothing to a governed call

Copy `.env.example` to `.env` and set `POSTGRES_PASSWORD` (letters and digits), `OPENAI_PROVIDER_KEY` and
`GANTRY_LICENSE`. Then:

```bash
docker compose up -d
KEY=$(docker compose run --rm -T cli key new noa.bar --team platform --policy /etc/gantry/gantry.policy.yaml --quiet)
curl -s http://127.0.0.1:8080/v1/chat/completions -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}]}'
```

`up` pulls `ghcr.io/ggantry/gantry-enterprise` (log in with `docker login ghcr.io` first) or, without access, builds
it from the folder that holds both repositories (`build.context` is three levels up). The `cli` service is the open
source `gantry` command line, built from the `gantry` repository beside this one, for `key new` and `audit verify`.

## Checks

```bash
curl -s http://127.0.0.1:8080/healthz
docker compose run --rm -T cli audit verify /var/lib/gantry/gantry-audit.jsonl
```

The first start prints a one-time link to make the first console admin: `docker compose logs gantry`.

## Notes

- Gantry shares the Postgres container's network, so the database is `localhost` to it and the connection needs no
  TLS (`sslmode=disable`; Gantry warns at start that it is not encrypted). That is why port 8080 is published on the
  `postgres` service.
- Gantry listens on `127.0.0.1:8080`. For other machines, set `GANTRY_BIND=0.0.0.0` and put TLS in front (Caddy or
  nginx, see the deployment docs) or give Gantry `--tls-cert` and `--tls-key`.
- One Gantry per `gantry-data` volume: two processes on one audit log break its chain.
- Back up both volumes. The audit log is the record of every decision; Postgres holds the keys.
- Upgrade: `docker compose pull && docker compose up -d`. Gantry waits up to 30 seconds for requests in flight.

## Test

`test/run.sh` starts the stack with an OpenAI-compatible mock (`test` profile), issues a key, makes a governed call,
checks that a call without a key is refused and verifies the audit chain. CI runs it on every change to `deploy/`.
