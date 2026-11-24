# cloudflare

Enterplace on Cloudflare: a Worker in front of gateway containers (Cloudflare Containers, one gateway per instance), the
audit chain in R2, and the store in a Durable Object. The only runtime dependencies are Cloudflare and the model
providers. The guide is `docs/deploy/cloudflare` on the docs site; this file is the short version.

## What it creates

| Resource | Why |
|---|---|
| Worker (`src/index.ts`) with a custom domain | Routes each request to one of `GATEWAYS` gateway instances, and serves `GET /_enterplace/audit/<instance>` |
| Durable Object class `EnterplaceGateway` and its container application | One Enterplace gateway per instance, built from `./Dockerfile` (the image plus your policy) |
| Durable Object class `EnterplaceStore`, bound as `STORE` (`src/store-object.ts`, `src/store.ts`) | The store every instance shares: keys, kill switches, budgets, rate limits, sessions, sealed credentials, policy versions, cache, routing and health, plus the tables of the request log, batches, MCP state and the Enterprise features, in the object's SQLite |
| R2 bucket binding `AUDIT` | Each instance's sealed audit segments, under `audit/<instance id>/` |
| Workers secrets | `ENTERPLACE_LICENSE`, `ENTERPLACE_MASTER_KEY`, `ENTERPLACE_EXPORT_KEY`, `ENTERPLACE_AUDIT_READ_TOKEN`, each `*_PROVIDER_KEY`. Passed to the container as environment variables |

## Why wrangler and not Terraform

`wrangler deploy` builds the image, pushes it to the account's registry, and deploys the Worker, the Durable Object
class, its migration and the container application together, and rolls the containers when the image changes. The
Cloudflare Terraform provider does not build or push images, so Terraform would need wrangler or a registry script
beside it anyway. One tool and one command is less to keep in step.

## How the audit chain survives a restart

A container's disk is new at every start. The gateway seals its audit log every `ENTERPLACE_AUDIT_SEAL_SECONDS` (60) or
at `ENTERPLACE_AUDIT_SEAL_BYTES` (1 MiB), writes each sealed segment to R2, and only then removes it from disk with an
`audit_retired` record that names it. On a graceful stop (a rollout, `sleepAfter`) it seals and writes the rest. On a
start with an empty disk it fetches the newest segments back and continues the chain from the last hash. A container
that is killed loses at most the records since the last seal.

The container reaches R2 through the Worker, not with an access key: the gateway sends S3 requests to
`http://audit.enterplace.internal`, and the Worker answers them from the `AUDIT` binding, scoped to that instance's
folder. It has no delete and refuses to overwrite a segment with other bytes.

## How the store works without a database

A container cannot use Worker bindings, so the gateway reaches the store as it reaches R2: with
`store: { cloudflare: true }` it sends each call to `http://store.enterplace.internal`, and the Worker forwards it to the
one `EnterplaceStore` object. The object runs one call at a time, so budget reservations, rate-limit leases, probe
leases and policy version changes are atomic across every instance. Gateways read keys and kill switches from memory
and poll the object twice a second; only a request under a budget or rate limit waits on it, and one is refused
(`store_unavailable`) while the object cannot be reached.

`src/store.ts` names no Workers API, so `test/store-server.ts` runs the same code on node:sqlite for the gateway's
store tests (`ENTERPLACE_TEST_STORE=cloudflare cargo test -p enterplace-server --test store`). For a check with the
real object, `npx wrangler dev -c test/wrangler.jsonc` serves it alone on workerd for gateways run on your machine
(`ENTERPLACE_CLOUDFLARE_STORE_URL=http://127.0.0.1:8787`). Never deploy that config.

## Use

```bash
docker create --name enterplace-files ghcr.io/eliransu/enterplace:<version>
docker cp enterplace-files:/deploy/cloudflare ./enterplace-cloudflare && docker rm enterplace-files
cd enterplace-cloudflare && npm ci
# Edit the lines marked EDIT in wrangler.jsonc, and enterplace.policy.yaml.
npx wrangler r2 bucket create enterplace-audit
npx wrangler deploy
npx wrangler secret put ENTERPLACE_LICENSE  # and OPENAI_PROVIDER_KEY, ENTERPLACE_MASTER_KEY, ENTERPLACE_AUDIT_READ_TOKEN, ...
```

Check the whole chain of instance `gateway-0`, R2 segments and unsealed tail together:

```bash
curl -s -H "Authorization: Bearer $ENTERPLACE_AUDIT_READ_TOKEN" https://enterplace.example.com/_enterplace/audit/gateway-0 > chain.jsonl
docker run --rm -v "$PWD":/w:ro ghcr.io/eliransu/enterplace:<version> audit verify /w/chain.jsonl
```

## Limits

- Containers need the Workers Paid plan.
- Every store call goes to one Durable Object (about 1,000 requests a second by Cloudflare's guidance, 10 GB of
  SQLite, most of it the request log: set retention). Past that, set `store: { postgres_url_env: DATABASE_URL }` and
  the `DATABASE_URL` secret: a Postgres reachable from the internet over TLS (`sslmode=require` or stricter) whose
  certificate chains to a public authority, such as Neon. A container cannot use Hyperdrive.
- Requests are spread at random, so single sign-on to the console needs `GATEWAYS` set to 1.
- Without a store, keys and budgets are per instance and spend is forgotten at restart: keep `store: { cloudflare: true }`.
