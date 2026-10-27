locals {
  secret_name = var.secret_values != null ? "${var.name}-secrets" : var.existing_secret

  base_values = {
    profile = var.profile
    image = {
      repository = var.image.repository
      tag        = var.image.tag
      digest     = var.image.digest
    }
    replicaCount = var.replicas
    postgres = {
      host     = var.postgres.host
      port     = var.postgres.port
      database = var.postgres.database
      user     = var.postgres.user
      ssl      = var.postgres.ssl
    }
    redis = {
      url      = var.redis.url
      tls      = var.redis.tls
      username = var.redis.username
    }
    secrets = {
      existingSecret  = local.secret_name
      createDevSecret = var.create_dev_secret
    }
    monitoring = {
      serviceMonitor = { enabled = var.monitoring }
      prometheusRule = { enabled = var.monitoring }
    }
  }
}

resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"             = "qodiqa"
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}

resource "kubernetes_secret_v1" "secrets" {
  count = var.secret_values != null ? 1 : 0

  metadata {
    name      = local.secret_name
    namespace = var.namespace
    labels    = { "app.kubernetes.io/name" = "qodiqa" }
  }

  data = var.secret_values
  type = "Opaque"

  depends_on = [kubernetes_namespace_v1.this]
}

resource "helm_release" "qodiqa" {
  name       = var.name
  namespace  = var.namespace
  chart      = var.chart_path
  repository = var.chart_repository
  version    = var.chart_version
  timeout    = var.timeout_seconds
  wait       = true
  atomic     = true

  values = compact([yamlencode(local.base_values), var.values])

  depends_on = [kubernetes_namespace_v1.this, kubernetes_secret_v1.secrets]

  lifecycle {
    precondition {
      condition     = var.profile == "development" || local.secret_name != ""
      error_message = "The production profile needs secret_values or existing_secret."
    }
  }
}
