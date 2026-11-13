output "service_name" {
  description = "The ECS service running the gateways."
  value       = aws_ecs_service.this.name
}

output "cluster_arn" {
  description = "The cluster the service runs in."
  value       = local.cluster_arn
}
