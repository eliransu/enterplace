# azurerm asks Entra ID for a token before it plans, so CI plans this example with the provider mocked: every
# resource is planned from the module's own configuration, and nothing reaches Azure.
mock_provider "azurerm" {}

run "plan" {
  command = plan

  assert {
    condition     = module.enterplace.revision_suffix != ""
    error_message = "the revision suffix, which names the audit log's folder, is empty"
  }

  assert {
    condition     = module.enterplace.master_key_secret == "enterplace-master-key" && module.enterplace.export_key_secret == "enterplace-export-key"
    error_message = "without master_key_secret and export_key_secret the module makes both keys in the vault"
  }
}
