# The example CI plans. azurerm needs a token before it can plan anything, so CI plans this example with
# `terraform test` and a mocked provider (tests/plan.tftest.hcl). With credentials, a plain `terraform plan` works.

provider "azurerm" {
  features {}
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

module "enterplace" {
  source = "../.."

  name                = "enterplace"
  location            = "westeurope"
  resource_group_name = "enterplace"
  image               = "ghcr.io/eliransu/enterplace:0.3.0"
  policy              = file("${path.module}/../../../enterplace.policy.yaml")

  key_vault_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/security/providers/Microsoft.KeyVault/vaults/acme-secrets"
  license_secret       = "enterplace-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
  registry = {
    server          = "ghcr.io"
    username        = "acme-bot"
    password_secret = "ghcr-token"
  }
}

output "gateway_url" {
  value = module.enterplace.gateway_url
}
