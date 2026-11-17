output "gateway_url" {
  description = "Where callers send requests: the service's HTTPS URL. Map a custom domain to it with a domain mapping or a load balancer."
  value       = google_cloud_run_v2_service.this.uri
}

output "service_name" {
  description = "The Cloud Run service."
  value       = google_cloud_run_v2_service.this.name
}

output "revision" {
  description = "The current revision, and the Filestore folder (under /enterplace) holding its audit log."
  value       = local.revision
}

output "sql_connection_name" {
  description = "The Cloud SQL instance's connection name."
  value       = google_sql_database_instance.this.connection_name
}

output "database_url_secret" {
  description = "The secret holding DATABASE_URL."
  value       = google_secret_manager_secret.database_url.secret_id
}

output "filestore_ip" {
  description = "The Filestore instance, for mounting the audit logs to verify or back them up."
  value       = google_filestore_instance.this.networks[0].ip_addresses[0]
}

output "service_account" {
  description = "The service account the gateway runs as, and Vertex AI providers sign in as."
  value       = google_service_account.enterplace.email
}

output "master_key_secret" {
  description = "The secret the gateway reads ENTERPLACE_MASTER_KEY from."
  value       = local.secrets["ENTERPLACE_MASTER_KEY"]
}

output "export_key_secret" {
  description = "The secret the gateway reads ENTERPLACE_EXPORT_KEY from."
  value       = local.secrets["ENTERPLACE_EXPORT_KEY"]
}
