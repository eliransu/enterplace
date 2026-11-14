output "gateway_url" {
  description = "Where callers send requests: the app's HTTPS address. Bind a custom domain and managed certificate to it for your own name."
  value       = "https://${azurerm_container_app.this.ingress[0].fqdn}"
}

output "container_app_name" {
  description = "The Container App."
  value       = azurerm_container_app.this.name
}

output "revision_suffix" {
  description = "The current revision, and the folder on the audit share holding its audit log."
  value       = local.revision
}

output "database_fqdn" {
  description = "The PostgreSQL server, reachable from the virtual network only."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "audit_share" {
  description = "The Azure Files share holding the audit logs, one folder per revision."
  value       = "${azurerm_storage_account.this.name}/${azurerm_storage_share.audit.name}"
}

output "outbound_ips" {
  description = "Addresses the gateway calls model providers from, for providers that allow-list callers."
  value       = azurerm_container_app.this.outbound_ip_addresses
}

output "master_key_secret" {
  description = "The Key Vault secret the gateway reads GANTRY_MASTER_KEY from."
  value       = local.vault_secrets["master-key"]
}

output "export_key_secret" {
  description = "The Key Vault secret the gateway reads GANTRY_EXPORT_KEY from."
  value       = local.vault_secrets["export-key"]
}
