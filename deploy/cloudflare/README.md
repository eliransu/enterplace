# cloudflare

Gantry on Cloudflare: a Worker in front of gateway containers (Cloudflare Containers, one gateway per instance), the
audit chain in R2, and the store in Postgres over TLS. The guide is `docs/deploy/cloudflare` on the docs site; this
file is the short version.

## What it creates

| Resource | Why |
|---|---|
| Worker (`src/index.ts`) with a custom domain | Routes each request to one of `GATEWAYS` gateway instances, and serves `GET /_gantry/audit/<instance>` |
| Durable Object class `GantryGateway` and its container application | One Gantry gateway per instance, built from `./Dockerfile` (the image plus your policy) |
| R2 bucket binding `AUDIT` | Each instance's sealed audit segments, under `audit/<instance id>/` |
| Workers secrets | `DATABASE_URL`, `GANTRY_LICENSE`, `GANTRY_MASTER_KEY`, `GANTRY_EXPORT_KEY`, `GANTRY_AUDIT_READ_TOKEN`, each `*_PROVIDER_KEY`. Passed to the container as environment variables |

## Why wrangler and not Terraform

`wrangler deploy` builds the image, pushes it to the account's registry, and deploys the Worker, the Durable Object
class, its migration and the container application together, and rolls the containers when the image changes. The
Cloudflare Terraform provider does not build or push images, so Terraform would need wrangler or a registry script
beside it anyway. One tool and one command is less to keep in step.

## How the audit chain survives a restart

A container's disk is new at every start. The gateway seals its audit log every `GANTRY_AUDIT_SEAL_SECONDS` (60) or
at `GANTRY_AUDIT_SEAL_BYTES` (1 MiB), writes each sealed segment to R2, and only then removes it from disk with an
`audit_retired` record that names it. On a graceful stop (a rollout, `sleepAfter`) it seals and writes the rest. On a
start with an empty disk it fetches the newest segments back and continues the chain from the last hash. A container
that is killed loses at most the records since the last seal.

The container reaches R2 through the Worker, not with an access key: the gateway sends S3 requests to
`http://audit.gantry.internal`, and the Worker answers them from the `AUDIT` binding, scoped to that instance's
folder. It has no delete and refuses to overwrite a segment with other bytes.

## Use

```bash
docker create --name gantry-files ghcr.io/ggantry/gantry:<version>
docker cp gantry-files:/deploy/cloudflare ./gantry-cloudflare && docker rm gantry-files
cd gantry-cloudflare && npm ci
# Edit the lines marked EDIT in wrangler.jsonc, and gantry.policy.yaml.
npx wrangler r2 bucket create gantry-audit
npx wrangler deploy
npx wrangler secret put DATABASE_URL        # and GANTRY_LICENSE, OPENAI_PROVIDER_KEY, GANTRY_AUDIT_READ_TOKEN, ...
```

Check the whole chain of instance `gateway-0`, R2 segments and unsealed tail together:

```bash
curl -s -H "Authorization: Bearer $GANTRY_AUDIT_READ_TOKEN" https://gantry.example.com/_gantry/audit/gateway-0 > chain.jsonl
docker run --rm -v "$PWD":/w:ro ghcr.io/ggantry/gantry:<version> audit verify /w/chain.jsonl
```

## Limits

- Containers need the Workers Paid plan.
- Hyperdrive is a binding for Worker code; a container reaches the Worker over HTTP only, so the gateway connects to
  Postgres directly over TLS (`DATABASE_URL`, `sslmode=require` or stricter). Use a Postgres reachable from the
  internet whose certificate chains to a public authority, such as Neon: Gantry checks it against the Mozilla roots
  built into it.
- Requests are spread at random, so single sign-on to the console needs `GATEWAYS` set to 1.
- Without a store, keys and budgets are per instance and spend is forgotten at restart: run with `store:`.
