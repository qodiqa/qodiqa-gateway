# Local cluster example (kind): the development profile against in-cluster PostgreSQL/Redis that you start yourself
# (deploy/helm/qodiqa/ci/fixtures.yaml). NOT for real traffic.
terraform {
  required_providers {
    helm       = { source = "hashicorp/helm", version = ">= 2.12, < 3.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.27, < 3.0" }
  }
}

variable "kube_config" {
  type    = string
  default = "~/.kube/config"
}

variable "kube_context" {
  type    = string
  default = "kind-qodiqa"
}

provider "kubernetes" {
  config_path    = var.kube_config
  config_context = var.kube_context
}

provider "helm" {
  kubernetes {
    config_path    = var.kube_config
    config_context = var.kube_context
  }
}

module "qodiqa" {
  source = "../../modules/qodiqa"

  chart_path        = "${path.module}/../../../helm/qodiqa"
  profile           = "development"
  create_dev_secret = true
  replicas          = 1
  image             = { repository = "qodiqa", tag = "local" }
  postgres          = { host = "pg", ssl = false }
  redis             = { url = "redis://redis:6379", tls = false }
  values = yamlencode({
    keystore       = { useEmptyDir = true }
    image          = { pullPolicy = "Never" }
    topologySpread = { enabled = false }
  })
}
