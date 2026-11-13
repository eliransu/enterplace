output "deployment_name" {
  description = "The Deployment running the gateways."
  value       = kubernetes_deployment_v1.this.metadata[0].name
}

output "service_name" {
  description = "The Service in front of the gateways."
  value       = kubernetes_service_v1.this.metadata[0].name
}

output "base_url" {
  description = "In-cluster address for OPENAI_BASE_URL (append /v1)."
  value       = "http://${kubernetes_service_v1.this.metadata[0].name}.${var.namespace}.svc.cluster.local:${var.service_port}"
}
