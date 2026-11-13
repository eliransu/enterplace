variable "name" {
  description = "Name of the service, cluster (if created), task family, role and log group."
  type        = string
  default     = "gantry-node"
}

variable "image" {
  description = "The gantry-enterprise image, such as 123456789012.dkr.ecr.eu-west-1.amazonaws.com/gantry-enterprise:1.4.0."
  type        = string
}

variable "control_plane_url" {
  description = "The Gantry control plane the node pulls its policy and keys from."
  type        = string
  default     = "https://gantry-control.eliran.me"
}

variable "node_token_secret_arn" {
  description = "Secrets Manager ARN of the node token (from the Gantry app, Gateways, or POST /admin/orgs/:org/nodes). Becomes GANTRY_NODE_TOKEN."
  type        = string
}

variable "provider_key_secret_arns" {
  description = "Provider keys: environment variable name the policy names => Secrets Manager ARN, such as { OPENAI_PROVIDER_KEY = \"arn:...\" }."
  type        = map(string)
  default     = {}
}

variable "subnets" {
  description = "Subnets for the tasks. They need outbound HTTPS to the control plane and the model providers."
  type        = list(string)
}

variable "security_groups" {
  description = "Security groups for the tasks. Allow inbound 8080 from the callers or the load balancer."
  type        = list(string)
}

variable "desired_count" {
  description = "How many gateway tasks to run."
  type        = number
  default     = 2
}

variable "cluster_arn" {
  description = "An existing ECS cluster. Leave null to create one named after var.name."
  type        = string
  default     = null
}

variable "target_group_arn" {
  description = "An ALB or NLB target group (target type ip, port 8080) to register the tasks in. Null for none."
  type        = string
  default     = null
}

variable "assign_public_ip" {
  description = "Give tasks a public IP. Needed only in public subnets without a NAT gateway."
  type        = bool
  default     = false
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

variable "poll_interval" {
  description = "Seconds between config checks with the control plane."
  type        = number
  default     = 5
}

variable "log_retention_days" {
  description = "CloudWatch retention for the gateway's logs."
  type        = number
  default     = 30
}
