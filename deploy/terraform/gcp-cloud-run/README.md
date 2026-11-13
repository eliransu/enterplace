# gcp-cloud-run

Gantry on Google Cloud: a Cloud Run service with one instance, Cloud SQL Postgres 16 for keys, kill switches and
budgets, the audit log on Filestore over NFS, and the policy and secrets in Secret Manager.

## What it creates

| Resource | Why |
|---|---|
| Cloud Run service (gen2, min and max 1 instance, CPU always on) | HTTPS on the service URL. CPU stays on because the gateway syncs its audit log and polls the store between requests |
| Cloud SQL Postgres 16 (regional, backups and point-in-time recovery), database and user | The store |
| Cloud SQL connector volume (`/cloudsql`) | Gantry connects over a Unix socket; see below |
| Filestore BASIC_HDD share `gantry`, mounted over NFS at `/var/lib/gantry` | The audit log, one folder per revision |
| Secret Manager secrets for `DATABASE_URL` and the policy | The policy is mounted as `/etc/gantry/gantry.policy.yaml` |
| Service account with `cloudsql.client` and access to each secret | What the gateway runs as |
| `allUsers` invoker (when `public = true`) | Gantry's own keys decide who may call |

**Cloud SQL through the connector, not a private IP.** Gantry checks the database's TLS certificate against the
Mozilla roots built into it. Cloud SQL's server certificates come from a per-instance authority that is not among
them, so a direct TLS connection, private or public, is refused. The connector authenticates with IAM, encrypts with
mutual TLS, and hands Gantry a local socket, where Gantry allows a connection without its own TLS. The instance has
a public IP with no authorized networks and requires client certificates, so nothing but the connector can reach it.

**Filestore, not Cloud Storage FUSE.** The audit log is one file Gantry appends to and syncs every second, with each
record chained to the one before. GCS FUSE writes whole objects on sync and has no locking, so a crash or a second
writer can cut the chain. NFS appends in place.

**One instance, one folder per revision.** Cloud Run cannot give each instance its own volume, and each gateway
needs its own chain, so the service runs exactly one instance. A deploy starts the new revision while the old one
drains, so the revision is named after a hash of its inputs and mounts its own folder (`sub_path`): each revision
writes a new chain and old chains stay on the share.

## Use

Create the provider key and license secrets in Secret Manager, and put the image in Artifact Registry (or a remote
repository in front of ghcr.io), then:

```hcl
module "gantry" {
  source = "github.com/ggantry/gantry-enterprise//deploy/terraform/gcp-cloud-run"

  project = "my-project"
  region  = "europe-west1"
  zone    = "europe-west1-b"
  image   = "europe-docker.pkg.dev/my-project/gantry/gantry-enterprise:0.1.0"
  policy  = file("gantry.policy.yaml")

  license_secret       = "gantry-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
}
```

The policy must have `audit: { path: /var/lib/gantry/gantry-audit.jsonl }` and
`store: { postgres_url_env: DATABASE_URL }`. Then issue a key and call the output `gateway_url`.

`examples/basic` is the configuration CI plans, with a fake access token and no Google account.

## Notes

- Filestore BASIC_HDD starts at 1 TiB. The `network` needs private services access only if you change the
  Filestore connect mode; the default (direct peering) needs nothing.
- The database password is in Terraform state. Keep the state encrypted.
- `deletion_protection` is on for the database and the service. Turn it off before `terraform destroy`.
- Organisation policies that forbid `allUsers` need `public = false`; callers then also send a Google identity token.
