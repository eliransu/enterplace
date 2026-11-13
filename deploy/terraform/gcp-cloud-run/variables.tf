variable "project" {
  description = "The Google Cloud project."
  type        = string
}

variable "region" {
  description = "Region for Cloud Run and Cloud SQL."
  type        = string
}

variable "zone" {
  description = "Zone for the Filestore instance (BASIC_HDD is zonal), in var.region."
  type        = string
}

variable "name" {
  description = "Prefix for every resource this module creates. Lowercase letters, digits and hyphens."
  type        = string
  default     = "gantry"
}

variable "image" {
  description = "The gantry-enterprise image. Cloud Run pulls from Artifact Registry (or a remote repository in front of ghcr.io), such as europe-docker.pkg.dev/my-project/gantry/gantry-enterprise:0.1.0."
  type        = string
}

variable "policy" {
  description = "The Gantry policy, as YAML text (for example file(\"gantry.policy.yaml\")). It must put the audit log under /var/lib/gantry and have `store: { postgres_url_env: DATABASE_URL }`. Stored in Secret Manager and mounted as /etc/gantry/gantry.policy.yaml; a change makes a new revision."
  type        = string
}

variable "network" {
  description = "VPC network (name or self link) for Filestore and the service's outbound traffic to it."
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Subnetwork in var.region for the service's Direct VPC egress."
  type        = string
  default     = "default"
}

variable "provider_key_secrets" {
  description = "Provider keys: the environment variable the policy's key_env names => Secret Manager secret ID in this project, such as { OPENAI_PROVIDER_KEY = \"openai-key\" }. The latest version is used. The module never reads the values."
  type        = map(string)
  default     = {}
}

variable "license_secret" {
  description = "Secret Manager secret ID of the Gantry license key. Becomes GANTRY_LICENSE. Null runs without the enterprise features."
  type        = string
  default     = null
}

variable "cpu" {
  description = "CPU of the instance."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Memory of the instance."
  type        = string
  default     = "1Gi"
}

variable "public" {
  description = "Let anyone reach the service URL. Gantry's own keys decide who may call; with false, callers also need a Google identity token with run.invoker."
  type        = bool
  default     = true
}

variable "ingress" {
  description = "Cloud Run ingress: INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY or INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER."
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"
}

variable "db_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-1-3840"
}

variable "db_availability_type" {
  description = "ZONAL, or REGIONAL for a standby in a second zone."
  type        = string
  default     = "REGIONAL"
}

variable "filestore_capacity_gb" {
  description = "Filestore capacity in GiB. BASIC_HDD starts at 1024."
  type        = number
  default     = 1024
}

variable "deletion_protection" {
  description = "Protect the database and service from deletion. Turn off before a terraform destroy."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels for every resource that takes them."
  type        = map(string)
  default     = {}
}
