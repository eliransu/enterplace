# A Gantry hybrid node on Kubernetes: a Deployment of gantry-enterprise in node mode and a Service in front of it.
# The node token and provider keys come from Secrets you already manage (External Secrets, Sealed Secrets, by hand);
# this module only references them, so their values never enter Terraform state.

terraform {
  required_version = ">= 1.5"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.20" }
  }
}

locals {
  labels = { "app.kubernetes.io/name" = "gantry", "app.kubernetes.io/instance" = var.name }
}

resource "kubernetes_deployment_v1" "this" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.labels
  }
  spec {
    replicas = var.replicas
    selector {
      match_labels = local.labels
    }
    template {
      metadata {
        labels = local.labels
      }
      spec {
        automount_service_account_token = false
        security_context {
          run_as_non_root = true
          run_as_user     = 65532
          run_as_group    = 65532
          fs_group        = 65532
        }
        container {
          name  = "gantry"
          image = var.image
          args  = ["node", "--control-plane", var.control_plane_url, "--dir", "/var/lib/gantry", "--listen", "0.0.0.0:8080", "--interval", tostring(var.poll_interval)]
          port {
            name           = "http"
            container_port = 8080
          }
          env {
            name = "GANTRY_NODE_TOKEN"
            value_from {
              secret_key_ref {
                name = var.node_token_secret.name
                key  = var.node_token_secret.key
              }
            }
          }
          dynamic "env" {
            for_each = var.provider_key_secrets
            content {
              name = env.key
              value_from {
                secret_key_ref {
                  name = env.value.name
                  key  = env.value.key
                }
              }
            }
          }
          readiness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 5
          }
          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            initial_delay_seconds = 30
            period_seconds        = 15
          }
          resources {
            requests = { cpu = var.cpu, memory = var.memory }
            limits   = { memory = var.memory }
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities {
              drop = ["ALL"]
            }
          }
          volume_mount {
            name       = "state"
            mount_path = "/var/lib/gantry"
          }
        }
        # The node's config cache and audit buffer. Use a PVC instead if audit must survive pod replacement.
        volume {
          name = "state"
          empty_dir {}
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "this" {
  metadata {
    name      = var.name
    namespace = var.namespace
    labels    = local.labels
  }
  spec {
    type     = var.service_type
    selector = local.labels
    port {
      name        = "http"
      port        = var.service_port
      target_port = "http"
    }
  }
}
