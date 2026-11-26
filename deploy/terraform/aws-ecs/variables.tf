variable "name" {
  description = "Prefix for every resource this module creates."
  type        = string
  default     = "enterplace"
}

variable "image" {
  description = "The enterplace image, such as ghcr.io/eliransu/enterplace:0.3.0. Pin a version: a moving tag makes rollbacks guesswork."
  type        = string
}

variable "image_pull_secret_arn" {
  description = "Secrets Manager ARN of registry credentials ({\"username\":...,\"password\":...}) for a private registry, such as your own mirror of the image. Null for ghcr.io/eliransu/enterplace (public) or ECR."
  type        = string
  default     = null
}

variable "policy" {
  description = "The Enterplace policy, as YAML text (for example file(\"enterplace.policy.yaml\")). It must put the audit log under /var/lib/enterplace and have `store: { postgres_url_env: DATABASE_URL }`. Stored in SSM Parameter Store; a change rolls the tasks."
  type        = string
}

variable "vpc_id" {
  description = "The VPC for the load balancer, tasks, database and file system."
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnets for the tasks, database and file system, in at least two availability zones. Tasks need outbound HTTPS to the model providers and the image registry (a NAT gateway or VPC endpoints)."
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Subnets for the load balancer, in at least two availability zones. Use private subnets with internal = true."
  type        = list(string)
}

variable "internal" {
  description = "Make the load balancer internal: reachable only inside the VPC and what is peered with it."
  type        = bool
  default     = false
}

variable "allowed_cidrs" {
  description = "Address ranges that may reach the load balancer on 443 (and 80, which redirects)."
  type        = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate for the load balancer's HTTPS listener, for domain_name."
  type        = string
}

variable "domain_name" {
  description = "The name callers use, covered by the certificate. You point it at the load balancer (output alb_dns_name). Null to use the load balancer's own name in gateway_url."
  type        = string
  default     = null
}

variable "replicas" {
  description = "How many gateways. Each is an ECS service of one task with its own EFS access point, because each gateway writes its own audit hash chain."
  type        = number
  default     = 2
  validation {
    condition     = var.replicas >= 1
    error_message = "replicas must be at least 1."
  }
}

variable "cpu" {
  description = "Fargate CPU units per task."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate memory per task, in MiB."
  type        = number
  default     = 1024
}

variable "cpu_architecture" {
  description = "X86_64 or ARM64, matching the image."
  type        = string
  default     = "X86_64"
}

variable "provider_key_secret_arns" {
  description = "Provider keys: the environment variable the policy's key_env names => Secrets Manager ARN, such as { OPENAI_PROVIDER_KEY = \"arn:aws:secretsmanager:...\" }. The module never reads the values, so they stay out of Terraform state."
  type        = map(string)
  default     = {}
}

variable "bedrock_resource_arns" {
  description = "Amazon Bedrock foundation-model and inference-profile ARNs the gateways may invoke, such as [\"arn:aws:bedrock:us-east-1::foundation-model/anthropic.*\", \"arn:aws:bedrock:us-east-1:123456789012:inference-profile/*\"]. Non-empty creates a task role allowed bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream on them, which Bedrock providers sign with: no AWS keys are stored. Empty or null creates no task role."
  type        = list(string)
  default     = []
}

variable "master_key_secret_arn" {
  description = "Optional. Secrets Manager ARN of the master key (64 hex characters) that seals provider credentials kept in the store. Becomes ENTERPLACE_MASTER_KEY. Null makes one with a random value in the secret <name>/master-key, kept across applies (its value is in Terraform state). Keep a copy outside AWS: a lost master key cannot be recovered."
  type        = string
  default     = null
}

variable "export_key_secret_arn" {
  description = "Optional. Secrets Manager ARN of the key (64 hex characters) that encrypts SIEM export destinations' secrets. Becomes ENTERPLACE_EXPORT_KEY. Null makes one with a random value in the secret <name>/export-key, kept across applies (its value is in Terraform state)."
  type        = string
  default     = null
}

variable "license_secret_arn" {
  description = "Secrets Manager ARN of the Enterplace license key. Becomes ENTERPLACE_LICENSE. Null runs without the enterprise features."
  type        = string
  default     = null
}

variable "database_url_secret_arn" {
  description = "Secrets Manager ARN of a DATABASE_URL for an existing Postgres. Null creates an RDS Postgres 16 and an RDS Proxy in front of it. An existing database must present a certificate that chains to a public root (Enterplace checks against the Mozilla roots), and allow the output task_security_group_id."
  type        = string
  default     = null
}

variable "db_instance_class" {
  description = "Instance class of the created database."
  type        = string
  default     = "db.t4g.small"
}

variable "db_allocated_storage" {
  description = "Storage of the created database, in GiB."
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Run the created database with a standby in a second availability zone."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Protect the database and load balancer from deletion. Turn off before a terraform destroy."
  type        = bool
  default     = true
}

variable "metrics_port" {
  description = "Serve Prometheus metrics on this port (enterplace serve --metrics). Null for none. Reachable only from metrics_cidrs, never through the load balancer."
  type        = number
  default     = null
}

variable "metrics_cidrs" {
  description = "Address ranges allowed to scrape metrics_port."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "CloudWatch retention for the gateways' logs."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
