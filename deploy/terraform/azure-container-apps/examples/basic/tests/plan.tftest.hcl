# azurerm asks Entra ID for a token before it plans, so CI plans this example with the provider mocked: every
# resource is planned from the module's own configuration, and nothing reaches Azure.
mock_provider "azurerm" {}

run "plan" {
  command = plan

  assert {
    condition     = module.gantry.revision_suffix != ""
    error_message = "the revision suffix, which names the audit log's folder, is empty"
  }
}
