variable "name" {
  description = "Prefix for every resource this module creates. Lowercase letters and digits, 3 to 16 characters (it also names the storage account)."
  type        = string
  default     = "enterplace"
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,15}$", var.name))
    error_message = "name must be 3 to 16 lowercase letters and digits, starting with a letter."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "The resource group to create for everything."
  type        = string
}

variable "image" {
  description = "The enterplace image, such as ghcr.io/eliransu/enterplace:0.3.0."
  type        = string
}

variable "registry" {
  description = "Credentials for a private registry: server, username, and the Key Vault secret (in key_vault_id) holding the password or token. Null for a public image."
  type = object({
    server          = string
    username        = string
    password_secret = string
  })
  default = null
}

variable "policy" {
  description = "The Enterplace policy, as YAML text (for example file(\"enterplace.policy.yaml\")). It must put the audit log under /var/lib/enterplace and have `store: { postgres_url_env: DATABASE_URL }`. A change makes a new revision."
  type        = string
}

variable "key_vault_id" {
  description = "An existing Key Vault with RBAC authorization holding the provider keys and the license. The module adds the DATABASE_URL secret (and the master and export keys it makes) to it (whoever runs Terraform needs Key Vault Secrets Officer) and lets the app read it."
  type        = string
}

variable "provider_key_secrets" {
  description = "Provider keys: the environment variable the policy's key_env names => secret name in key_vault_id, such as { OPENAI_PROVIDER_KEY = \"openai-key\" }. The module never reads the values."
  type        = map(string)
  default     = {}
}

variable "master_key_secret" {
  description = "Optional. Secret name in key_vault_id holding the master key (64 hex characters) that seals provider credentials kept in the store. Becomes ENTERPLACE_MASTER_KEY. Null makes one with a random value as the secret <name>-master-key, kept across applies (its value is in Terraform state). Keep a copy elsewhere: a lost master key cannot be recovered."
  type        = string
  default     = null
}

variable "export_key_secret" {
  description = "Optional. Secret name in key_vault_id holding the key (64 hex characters) that encrypts SIEM export destinations' secrets. Becomes ENTERPLACE_EXPORT_KEY. Null makes one with a random value as the secret <name>-export-key, kept across applies (its value is in Terraform state)."
  type        = string
  default     = null
}

variable "license_secret" {
  description = "Secret name in key_vault_id holding the Enterplace license key. Becomes ENTERPLACE_LICENSE. Null runs without the enterprise features."
  type        = string
  default     = null
}

variable "vnet_address_space" {
  description = "Address space of the virtual network the module creates."
  type        = string
  default     = "10.40.0.0/16"
}

variable "internal" {
  description = "Make the environment internal: the app is reachable only inside the virtual network."
  type        = bool
  default     = false
}

variable "allowed_cidrs" {
  description = "Address ranges allowed to reach the app. Empty allows all; Enterplace's keys still decide who may call."
  type        = list(string)
  default     = []
}

variable "cpu" {
  description = "CPU cores of the app (Consumption: 0.25 to 4, in steps of 0.25)."
  type        = number
  default     = 1
}

variable "memory" {
  description = "Memory of the app, twice the CPU on Consumption, such as 2Gi."
  type        = string
  default     = "2Gi"
}

variable "db_sku" {
  description = "Azure Database for PostgreSQL Flexible Server SKU."
  type        = string
  default     = "GP_Standard_D2ds_v5"
}

variable "db_storage_mb" {
  description = "Database storage, in MB."
  type        = number
  default     = 32768
}

variable "db_high_availability" {
  description = "Run the database with a zone-redundant standby."
  type        = bool
  default     = false
}

variable "audit_share_quota_gb" {
  description = "Size of the Azure Files share for the audit logs, in GiB."
  type        = number
  default     = 100
}

variable "log_retention_days" {
  description = "Log Analytics retention for the app's logs."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
