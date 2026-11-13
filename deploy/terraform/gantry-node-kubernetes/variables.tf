variable "name" {
  description = "Name of the Deployment and Service."
  type        = string
  default     = "gantry"
}

variable "namespace" {
  description = "Namespace to run in. It must exist and hold the Secrets below."
  type        = string
  default     = "default"
}

variable "image" {
  description = "The gantry-enterprise image, such as registry.example.com/gantry-enterprise:1.4.0."
  type        = string
}

variable "control_plane_url" {
  description = "The Gantry control plane the node pulls its policy and keys from."
  type        = string
  default     = "https://gantry-control.eliran.me"
}

variable "node_token_secret" {
  description = "The Secret holding the node token (from the Gantry app, Gateways). Becomes GANTRY_NODE_TOKEN."
  type        = object({ name = string, key = string })
}

variable "provider_key_secrets" {
  description = "Provider keys: environment variable name the policy names => Secret name and key, such as { OPENAI_PROVIDER_KEY = { name = \"llm-keys\", key = \"openai\" } }."
  type        = map(object({ name = string, key = string }))
  default     = {}
}

variable "replicas" {
  description = "How many gateway pods to run."
  type        = number
  default     = 2
}

variable "service_type" {
  description = "ClusterIP for in-cluster callers, LoadBalancer to expose it."
  type        = string
  default     = "ClusterIP"
}

variable "service_port" {
  description = "Port the Service listens on."
  type        = number
  default     = 80
}

variable "cpu" {
  description = "CPU request per pod."
  type        = string
  default     = "250m"
}

variable "memory" {
  description = "Memory request and limit per pod."
  type        = string
  default     = "256Mi"
}

variable "poll_interval" {
  description = "Seconds between config checks with the control plane."
  type        = number
  default     = 5
}
