# azure-container-apps

Gantry on Azure: a Container App with HTTPS ingress, Azure Database for PostgreSQL Flexible Server 16 for keys,
kill switches and budgets, the audit log on Azure Files, and secrets as Key Vault references.

## What it creates

| Resource | Why |
|---|---|
| Resource group, virtual network with a subnet for the apps and a delegated subnet for the database | Private network for everything |
| Container Apps environment (Consumption workload profile) and app (one replica, single revision mode) | HTTPS ingress on the app's address, health probes on `/healthz` |
| PostgreSQL Flexible Server 16, private access only, private DNS zone, database `gantry` | The store. Its certificate chains to roots Gantry trusts, so it connects with `sslmode=verify-full`, checking the certificate and host name |
| Key Vault secret `<name>-database-url` in your vault | The app reads `DATABASE_URL`, the provider keys and the license as Key Vault references |
| User-assigned identity with Key Vault Secrets User on the vault | What the app reads secrets as |
| Storage account (ZRS) and Azure Files share, mounted at `/var/lib/gantry` | The audit log, one folder per revision |
| busybox init container and an EmptyDir volume | Writes the policy to `/etc/gantry/gantry.policy.yaml`: the image has no shell |
| Log Analytics workspace | The app's logs |

**One replica, one folder per revision.** Container Apps cannot give each replica its own volume, and each gateway
needs its own chain, so the app runs exactly one replica. A deploy starts the new revision while the old one drains,
so the revision suffix is a hash of its inputs and the revision mounts its own folder (`sub_path`): each revision
writes a new chain and old chains stay on the share.

## Use

Put the provider keys and the license in a Key Vault that uses RBAC authorization. Whoever runs Terraform needs Key
Vault Secrets Officer on it (to add `DATABASE_URL`). Then:

```hcl
module "gantry" {
  # Copied out of the image: docker create --name gantry-files ghcr.io/ggantry/gantry-enterprise:<version>
  #   && docker cp gantry-files:/deploy ./gantry-deploy && docker rm gantry-files
  source = "./gantry-deploy/terraform/azure-container-apps"

  location            = "westeurope"
  resource_group_name = "gantry"
  image               = "ghcr.io/ggantry/gantry-enterprise:0.1.0"
  policy              = file("gantry.policy.yaml")

  key_vault_id         = "/subscriptions/.../providers/Microsoft.KeyVault/vaults/acme-secrets"
  license_secret       = "gantry-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
  registry             = { server = "ghcr.io", username = "acme-bot", password_secret = "ghcr-token" }
}
```

The policy must have `audit: { path: /var/lib/gantry/gantry-audit.jsonl }` and
`store: { postgres_url_env: DATABASE_URL }`. Then issue a key and call the output `gateway_url`.

`examples/basic` is the configuration CI plans. azurerm needs an Entra ID token before it plans anything, so CI runs
`terraform test` there, which plans the example with the provider mocked.

## Notes

- The database password and the storage account key are in Terraform state. Keep the state encrypted.
- A new role assignment can take minutes to reach Key Vault; if the first apply fails to read a secret, apply again.
