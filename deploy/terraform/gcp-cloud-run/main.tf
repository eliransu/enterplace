# Gantry on Google Cloud: one Cloud Run instance, Cloud SQL Postgres through the Cloud SQL connector, the audit log
# on Filestore over NFS, secrets and the policy in Secret Manager. See README.md for why each was chosen.

locals {
  # Every input that changes the revision's template. The revision is named after it, and so is the audit log's
  # folder on Filestore: a new revision starts a new chain in a new folder while the old one drains, so two
  # instances never write one chain.
  revision = "${var.name}-${substr(sha256(jsonencode({
    image   = var.image
    policy  = var.policy
    keys    = var.provider_key_secrets
    license = var.license_secret
    cpu     = var.cpu
    memory  = var.memory
  })), 0, 10)}"
  # The connector's Unix socket. Gantry allows a connection without TLS only to its own machine, and a socket is.
  socket_dir = "/cloudsql/${google_sql_database_instance.this.connection_name}"
  secrets = merge(
    { DATABASE_URL = google_secret_manager_secret.database_url.secret_id },
    var.license_secret == null ? {} : { GANTRY_LICENSE = var.license_secret },
    var.provider_key_secrets,
  )
}

resource "google_project_service" "this" {
  for_each           = toset(["run.googleapis.com", "sqladmin.googleapis.com", "file.googleapis.com", "secretmanager.googleapis.com"])
  project            = var.project
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "gantry" {
  project      = var.project
  account_id   = "${var.name}-run"
  display_name = "Gantry gateway"
}

resource "google_project_iam_member" "sql_client" {
  project = var.project
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.gantry.email}"
}

resource "google_secret_manager_secret_iam_member" "gantry" {
  for_each  = merge(local.secrets, { policy = google_secret_manager_secret.policy.secret_id })
  project   = var.project
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gantry.email}"
}

# Cloud SQL. Public IP with no authorized networks and client certificates required: only the Cloud SQL connector
# (IAM-authorized, mutual TLS) can connect. Private IP is not used because Cloud SQL's server certificates come from
# a per-instance authority that is not among the Mozilla roots Gantry checks against, so a direct TLS connection is
# refused; the connector gives Gantry a local socket instead.
resource "google_sql_database_instance" "this" {
  project             = var.project
  name                = var.name
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection
  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE"
    availability_type = var.db_availability_type
    user_labels       = var.labels
    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }
  depends_on = [google_project_service.this]
}

resource "google_sql_database" "gantry" {
  project  = var.project
  instance = google_sql_database_instance.this.name
  name     = "gantry"
}

resource "random_password" "db" {
  # Letters and digits only: the password goes into a connection string unescaped.
  length  = 32
  special = false
}

resource "google_sql_user" "gantry" {
  project  = var.project
  instance = google_sql_database_instance.this.name
  name     = "gantry"
  password = random_password.db.result
}

resource "google_secret_manager_secret" "database_url" {
  project   = var.project
  secret_id = "${var.name}-database-url"
  labels    = var.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret      = google_secret_manager_secret.database_url.id
  secret_data = "postgres://gantry:${random_password.db.result}@${urlencode(local.socket_dir)}/gantry?sslmode=disable"
}

# The policy as a secret, because Cloud Run mounts secrets as files. It holds no secrets itself.
resource "google_secret_manager_secret" "policy" {
  project   = var.project
  secret_id = "${var.name}-policy"
  labels    = var.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.this]
}

resource "google_secret_manager_secret_version" "policy" {
  secret      = google_secret_manager_secret.policy.id
  secret_data = var.policy
}

# Filestore over NFS for the audit log. Cloud Storage FUSE is not used: Gantry appends to the log and syncs it every
# second, and GCS FUSE rewrites a whole object on each sync with no locking, so a crash or a second writer can cut
# the hash chain. NFS appends in place.
resource "google_filestore_instance" "this" {
  project  = var.project
  name     = var.name
  location = var.zone
  tier     = "BASIC_HDD"
  labels   = var.labels
  file_shares {
    name        = "gantry"
    capacity_gb = var.filestore_capacity_gb
    # Writes as root (Cloud Run creating the revision's folder) are mapped to the image's user, 65532, so the
    # gateway owns its folder.
    nfs_export_options {
      ip_ranges   = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      access_mode = "READ_WRITE"
      squash_mode = "ROOT_SQUASH"
      anon_uid    = 65532
      anon_gid    = 65532
    }
  }
  networks {
    network = var.network
    modes   = ["MODE_IPV4"]
  }
  depends_on = [google_project_service.this]
}

resource "google_cloud_run_v2_service" "this" {
  project             = var.project
  name                = var.name
  location            = var.region
  ingress             = var.ingress
  deletion_protection = var.deletion_protection
  labels              = var.labels

  template {
    revision                         = local.revision
    service_account                  = google_service_account.gantry.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = 1000
    # Streams can run long; Cloud Run's limit is an hour.
    timeout = "3600s"
    # One instance: Cloud Run cannot give each instance its own folder, and each gateway needs its own chain.
    # ponytail: one gateway; for more, run this module once per replica behind one load balancer.
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }
    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = var.network
        subnetwork = var.subnetwork
      }
    }
    containers {
      image = var.image
      args  = ["serve", "/etc/gantry/gantry.policy.yaml", "--listen", "0.0.0.0:8080"]
      ports {
        container_port = 8080
      }
      resources {
        limits = { cpu = var.cpu, memory = var.memory }
        # The gateway syncs its audit log and polls the store between requests, so it keeps its CPU.
        cpu_idle          = false
        startup_cpu_boost = true
      }
      dynamic "env" {
        for_each = local.secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
      volume_mounts {
        name       = "policy"
        mount_path = "/etc/gantry"
      }
      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }
      volume_mounts {
        name       = "audit"
        mount_path = "/var/lib/gantry"
        sub_path   = local.revision
      }
      startup_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds    = 2
        failure_threshold = 30
      }
      liveness_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds    = 10
        failure_threshold = 6
      }
    }
    volumes {
      name = "policy"
      secret {
        secret = google_secret_manager_secret.policy.secret_id
        items {
          version = google_secret_manager_secret_version.policy.version
          path    = "gantry.policy.yaml"
        }
      }
    }
    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.this.connection_name]
      }
    }
    volumes {
      name = "audit"
      nfs {
        server = google_filestore_instance.this.networks[0].ip_addresses[0]
        path   = "/gantry"
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.gantry, google_project_iam_member.sql_client, google_secret_manager_secret_version.database_url]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  count    = var.public ? 1 : 0
  project  = var.project
  location = var.region
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
