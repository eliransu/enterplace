# gcp-cloud-run

Enterplace on Google Cloud: a Cloud Run service with one instance, Cloud SQL Postgres 16 for keys, kill switches and
budgets, the audit log on Filestore over NFS, and the policy and secrets in Secret Manager.

## What it creates

| Resource | Why |
|---|---|
| Cloud Run service (gen2, min and max 1 instance, CPU always on) | HTTPS on the service URL. CPU stays on because the gateway syncs its audit log and polls the store between requests |
| Cloud SQL Postgres 16 (regional, backups and point-in-time recovery), database and user | The store |
| Cloud SQL connector volume (`/cloudsql`) | Enterplace connects over a Unix socket; see below |
| Filestore BASIC_HDD share `enterplace`, mounted over NFS at `/var/lib/enterplace` | The audit log, one folder per revision |
| Secret Manager secrets for `DATABASE_URL` and the policy | The policy is mounted as `/etc/enterplace/enterplace.policy.yaml` |
| Secret Manager secrets `<name>-master-key` and `<name>-export-key`, random 64 hex characters each | `ENTERPLACE_MASTER_KEY` (seals provider credentials in the store) and `ENTERPLACE_EXPORT_KEY` (encrypts SIEM destination secrets). Made once and kept across applies; skipped for a key you pass as `master_key_secret` or `export_key_secret` |
| Service account with `cloudsql.client`, `aiplatform.user` (when `vertex_ai = true`, the default) and access to each secret | What the gateway runs as, and what Vertex AI providers sign in as |
| `allUsers` invoker (when `public = true`) | Enterplace's own keys decide who may call |

**Cloud SQL through the connector, not a private IP.** Enterplace checks the database's TLS certificate against the
Mozilla roots built into it. Cloud SQL's server certificates come from a per-instance authority that is not among
them, so a direct TLS connection, private or public, is refused. The connector authenticates with IAM, encrypts with
mutual TLS, and hands Enterplace a local socket, where Enterplace allows a connection without its own TLS. The instance has
a public IP with no authorized networks and requires client certificates, so nothing but the connector can reach it.

**Filestore, not Cloud Storage FUSE.** The audit log is one file Enterplace appends to and syncs every second, with each
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
module "enterplace" {
  # Copied out of the image: docker create --name enterplace-files ghcr.io/eliransu/enterplace:<version>
  #   && docker cp enterplace-files:/deploy ./enterplace-deploy && docker rm enterplace-files
  source = "./enterplace-deploy/terraform/gcp-cloud-run"

  project = "my-project"
  region  = "europe-west1"
  zone    = "europe-west1-b"
  image   = "europe-docker.pkg.dev/my-project/enterplace/enterplace:0.1.0"
  policy  = file("enterplace.policy.yaml")

  license_secret       = "enterplace-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
}
```

The policy must have `audit: { path: /var/lib/enterplace/enterplace-audit.jsonl }` and
`store: { postgres_url_env: DATABASE_URL }`. Then issue a key and call the output `gateway_url`.

`examples/basic` is the configuration CI plans, with a fake access token and no Google account.

## Notes

- Filestore BASIC_HDD starts at 1 TiB. The `network` needs private services access only if you change the
  Filestore connect mode; the default (direct peering) needs nothing.
- The database password is in Terraform state, and so are the master and export keys the module makes. Keep the
  state encrypted, and a copy of the master key elsewhere: a lost one cannot be recovered.
- Vertex AI providers (`vertex`, `vertex_anthropic`) sign in as the service account through the metadata server:
  leave `key_env` out of them and store no access token. `vertex_ai = false` drops the role and the API.
- `deletion_protection` is on for the database and the service. Turn it off before `terraform destroy`.
- Organisation policies that forbid `allUsers` need `public = false`; callers then also send a Google identity token.
