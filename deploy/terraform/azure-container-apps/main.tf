# Enterplace on Azure: one Container App with HTTPS ingress, Azure Database for PostgreSQL Flexible Server on a private
# network, the audit log on Azure Files, and secrets as Key Vault references. See README.md.

locals {
  # Every input that changes the revision's template. The revision is named after it, and so is the audit log's
  # folder on the share: a new revision starts a new chain in a new folder while the old one drains, so two
  # replicas never write one chain.
  # Revision suffixes must start with a letter.
  revision = "r${substr(sha256(jsonencode({
    image    = var.image
    policy   = var.policy
    keys     = var.provider_key_secrets
    license  = var.license_secret
    master   = var.master_key_secret
    export   = var.export_key_secret
    registry = var.registry
    cpu      = var.cpu
    memory   = var.memory
  })), 0, 10)}"
  vault_uri = "https://${element(split("/", var.key_vault_id), length(split("/", var.key_vault_id)) - 1)}.vault.azure.net/secrets/"
  # The keys the caller did not pass, which the module makes.
  generated_keys = toset(concat(
    var.master_key_secret == null ? ["master-key"] : [],
    var.export_key_secret == null ? ["export-key"] : [],
  ))
  # Container App secret name => Key Vault secret name, for every secret the gateway reads from the vault.
  vault_secrets = merge(
    {
      database-url = azurerm_key_vault_secret.database_url.name
      master-key   = var.master_key_secret == null ? azurerm_key_vault_secret.generated["master-key"].name : var.master_key_secret
      export-key   = var.export_key_secret == null ? azurerm_key_vault_secret.generated["export-key"].name : var.export_key_secret
    },
    var.license_secret == null ? {} : { license = var.license_secret },
    { for env_name, secret in var.provider_key_secrets : "key-${lower(replace(env_name, "_", "-"))}" => secret },
    var.registry == null ? {} : { registry-password = var.registry.password_secret },
  )
  env_secrets = merge(
    { DATABASE_URL = "database-url", ENTERPLACE_MASTER_KEY = "master-key", ENTERPLACE_EXPORT_KEY = "export-key" },
    var.license_secret == null ? {} : { ENTERPLACE_LICENSE = "license" },
    { for env_name, _ in var.provider_key_secrets : env_name => "key-${lower(replace(env_name, "_", "-"))}" },
  )
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "apps" {
  name                 = "apps"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space, 7, 0)]
  delegation {
    name = "apps"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "db" {
  name                 = "db"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space, 8, 2)]
  delegation {
    name = "postgres"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# The database: private access only, reachable from the virtual network. Its certificate chains to DigiCert and
# Microsoft roots that are among the Mozilla roots Enterplace checks against, so Enterplace connects with sslmode=verify-full.
resource "azurerm_private_dns_zone" "db" {
  name                = "${var.name}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "db" {
  name                = "${var.name}-db"
  private_dns_zone_id = azurerm_private_dns_zone.db.id
  virtual_network_id  = azurerm_virtual_network.this.id
  tags                = var.tags
}

resource "random_password" "db" {
  # Letters and digits only: the password goes into a connection string unescaped.
  length  = 32
  special = false
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = var.name
  resource_group_name           = azurerm_resource_group.this.name
  location                      = var.location
  version                       = "16"
  sku_name                      = var.db_sku
  storage_mb                    = var.db_storage_mb
  backup_retention_days         = 7
  delegated_subnet_id           = azurerm_subnet.db.id
  private_dns_zone_id           = azurerm_private_dns_zone.db.id
  public_network_access_enabled = false
  administrator_login           = "enterplace"
  administrator_password        = random_password.db.result
  dynamic "high_availability" {
    for_each = var.db_high_availability ? [1] : []
    content {
      mode = "ZoneRedundant"
    }
  }
  tags       = var.tags
  depends_on = [azurerm_private_dns_zone_virtual_network_link.db]
  lifecycle {
    # Azure picks the zone when none is given; a later plan must not try to move the server.
    ignore_changes = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "enterplace" {
  name      = "enterplace"
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_key_vault_secret" "database_url" {
  name         = "${var.name}-database-url"
  key_vault_id = var.key_vault_id
  value        = "postgres://enterplace:${random_password.db.result}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/enterplace?sslmode=verify-full"
}

# The master key (seals provider credentials kept in the store) and the export key (encrypts SIEM destination
# secrets): 64 hex characters each. A key the caller does not pass is made here, once: random_bytes keeps its value
# in state, so later applies leave it as it is.
resource "random_bytes" "key" {
  for_each = local.generated_keys
  length   = 32
}

resource "azurerm_key_vault_secret" "generated" {
  for_each     = local.generated_keys
  name         = "${var.name}-${each.key}"
  key_vault_id = var.key_vault_id
  value        = random_bytes.key[each.key].hex
}

# The app reads its secrets from the vault as this identity.
resource "azurerm_user_assigned_identity" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_role_assignment" "vault" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

# Azure Files for the audit logs.
resource "azurerm_storage_account" "this" {
  # Storage account names are global: a hash of the resource group makes this one unlikely to be taken.
  name                            = "${var.name}${substr(sha256(azurerm_resource_group.this.id), 0, 8)}"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "ZRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = var.tags
}

resource "azurerm_storage_share" "audit" {
  name               = "enterplace-audit"
  storage_account_id = azurerm_storage_account.this.id
  quota              = var.audit_share_quota_gb
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

resource "azurerm_container_app_environment" "this" {
  name                           = var.name
  location                       = var.location
  resource_group_name            = azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = azurerm_subnet.apps.id
  internal_load_balancer_enabled = var.internal
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
  tags = var.tags
}

resource "azurerm_container_app_environment_storage" "audit" {
  name                         = "audit"
  container_app_environment_id = azurerm_container_app_environment.this.id
  account_name                 = azurerm_storage_account.this.name
  share_name                   = azurerm_storage_share.audit.name
  access_key                   = azurerm_storage_account.this.primary_access_key
  access_mode                  = "ReadWrite"
}

resource "azurerm_container_app" "this" {
  name                         = var.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  dynamic "secret" {
    for_each = local.vault_secrets
    content {
      name                = secret.key
      key_vault_secret_id = "${local.vault_uri}${secret.value}"
      identity            = azurerm_user_assigned_identity.this.id
    }
  }

  # The policy holds no secrets; it is an app secret only so the init container can receive it as a variable.
  secret {
    name  = "policy"
    value = var.policy
  }

  dynamic "registry" {
    for_each = var.registry == null ? [] : [var.registry]
    content {
      server               = registry.value.server
      username             = registry.value.username
      password_secret_name = "registry-password"
    }
  }

  ingress {
    external_enabled           = true
    target_port                = 8080
    transport                  = "http"
    allow_insecure_connections = false
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
    dynamic "ip_security_restriction" {
      for_each = var.allowed_cidrs
      content {
        name             = "allow-${ip_security_restriction.key}"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
      }
    }
  }

  template {
    revision_suffix = local.revision
    # One replica: Container Apps cannot give each replica its own folder, and each gateway needs its own chain.
    # ponytail: one gateway; for more, run this module's app once per replica behind one Front Door.
    min_replicas = 1
    max_replicas = 1
    # SIGTERM gives requests in flight 30 seconds; the margin lets the audit log sync before the kill.
    termination_grace_period_seconds = 40

    # The image has no shell, so this writes the policy from a variable into a file the gateway reads.
    init_container {
      name    = "policy"
      image   = "docker.io/library/busybox:1.36"
      cpu     = 0.25
      memory  = "0.5Gi"
      command = ["sh", "-c", "printf '%s' \"$ENTERPLACE_POLICY\" > /etc/enterplace/enterplace.policy.yaml"]
      env {
        name        = "ENTERPLACE_POLICY"
        secret_name = "policy"
      }
      volume_mounts {
        name = "policy"
        path = "/etc/enterplace"
      }
    }

    container {
      name   = "enterplace"
      image  = var.image
      cpu    = var.cpu
      memory = var.memory
      args   = ["serve", "/etc/enterplace/enterplace.policy.yaml", "--listen", "0.0.0.0:8080"]
      dynamic "env" {
        for_each = local.env_secrets
        content {
          name        = env.key
          secret_name = env.value
        }
      }
      volume_mounts {
        name = "policy"
        path = "/etc/enterplace"
      }
      volume_mounts {
        name     = "audit"
        path     = "/var/lib/enterplace"
        sub_path = local.revision
      }
      startup_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 2
        failure_count_threshold = 30
      }
      liveness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 10
        failure_count_threshold = 6
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/healthz"
      }
    }

    volume {
      name         = "policy"
      storage_type = "EmptyDir"
    }
    volume {
      name         = "audit"
      storage_type = "AzureFile"
      storage_name = azurerm_container_app_environment_storage.audit.name
      # SMB has no Unix owners; these make the files the image's user's, readable by it alone.
      mount_options = "uid=65532,gid=65532,dir_mode=0700,file_mode=0600"
    }
  }

  depends_on = [azurerm_role_assignment.vault]
}
