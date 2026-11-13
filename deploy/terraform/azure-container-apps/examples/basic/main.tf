# The example CI plans. azurerm needs a token before it can plan anything, so CI plans this example with
# `terraform test` and a mocked provider (tests/plan.tftest.hcl). With credentials, a plain `terraform plan` works.

provider "azurerm" {
  features {}
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

module "gantry" {
  source = "../.."

  name                = "gantry"
  location            = "westeurope"
  resource_group_name = "gantry"
  image               = "ghcr.io/ggantry/gantry-enterprise:0.1.0"
  policy              = file("${path.module}/../../../gantry.policy.yaml")

  key_vault_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/security/providers/Microsoft.KeyVault/vaults/acme-secrets"
  license_secret       = "gantry-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
  registry = {
    server          = "ghcr.io"
    username        = "acme-bot"
    password_secret = "ghcr-token"
  }
}

output "gateway_url" {
  value = module.gantry.gateway_url
}
