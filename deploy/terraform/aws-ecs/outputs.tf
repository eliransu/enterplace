output "gateway_url" {
  description = "Where callers send requests: https://<domain_name or the load balancer's name>."
  value       = local.gateway_url
}

output "alb_dns_name" {
  description = "Point domain_name here (a CNAME, or a Route 53 alias with alb_zone_id)."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "The load balancer's hosted zone, for a Route 53 alias."
  value       = aws_lb.this.zone_id
}

output "service_names" {
  description = "One ECS service per gateway."
  value       = [for s in aws_ecs_service.replica : s.name]
}

output "cluster_name" {
  description = "The ECS cluster."
  value       = aws_ecs_cluster.this.name
}

output "task_security_group_id" {
  description = "The gateways' security group. Allow it on an existing database."
  value       = aws_security_group.task.id
}

output "database_url_secret_arn" {
  description = "The secret the gateways read DATABASE_URL from."
  value       = local.database_url_secret_arn
}

output "efs_file_system_id" {
  description = "The file system holding each gateway's audit log, at /gantry-<n>."
  value       = aws_efs_file_system.this.id
}

output "policy_parameter_name" {
  description = "The Parameter Store parameter holding the policy."
  value       = aws_ssm_parameter.policy.name
}

output "log_group_name" {
  description = "CloudWatch log group of the gateways."
  value       = aws_cloudwatch_log_group.this.name
}
