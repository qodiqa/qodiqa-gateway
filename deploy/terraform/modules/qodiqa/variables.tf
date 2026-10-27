variable "name" {
  description = "Release name."
  type        = string
  default     = "qodiqa"
}

variable "namespace" {
  description = "Namespace for the gateway (created when create_namespace is true)."
  type        = string
  default     = "qodiqa"
}

variable "create_namespace" {
  type    = bool
  default = true
}

variable "chart_path" {
  description = "Path to the chart directory (deploy/helm/qodiqa) or, with chart_repository set, the chart name."
  type        = string
}

variable "chart_repository" {
  description = "Chart repository URL; null installs from chart_path on disk."
  type        = string
  default     = null
}

variable "chart_version" {
  description = "Chart version when installing from a repository."
  type        = string
  default     = null
}

variable "profile" {
  description = "production (default) or development (local clusters only: plain-text PostgreSQL/Redis, throw-away secrets)."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "development"], var.profile)
    error_message = "profile must be \"production\" or \"development\"."
  }
}

variable "image" {
  description = "Gateway image."
  type = object({
    repository = string
    tag        = optional(string, "")
    digest     = optional(string, "")
  })
}

variable "replicas" {
  description = "Gateway replicas. The production profile is single-node (the gateway refuses distributed mode in production), so 1; more only with profile = development."
  type        = number
  default     = 1
}

variable "postgres" {
  description = "PostgreSQL the gateway uses (an existing service; this module does not create a database)."
  type = object({
    host     = string
    port     = optional(number, 5432)
    database = optional(string, "qodiqa")
    user     = optional(string, "qodiqa_app")
    ssl      = optional(bool, true)
  })
}

variable "redis" {
  description = "Redis the gateway uses (an existing service)."
  type = object({
    url      = string
    tls      = optional(bool, true)
    username = optional(string, "qodiqa")
  })
}

variable "secret_values" {
  description = <<-EOT
    Production secrets, written into a Kubernetes Secret by this module (they are then also in the Terraform state: protect the state, or leave this null and create the Secret
    with your secret manager, passing its name in existing_secret). Keys: key-encryption-key, client-id, redis-password, postgres-password, postgres-retention-password,
    postgres-system-password, postgres-reporting-password, postgres-control-password, postgres-mig-password, execution-invariant-secret, dsr-pseudonym-pepper.
  EOT
  type        = map(string)
  default     = null
  sensitive   = true
}

variable "existing_secret" {
  description = "Name of a Secret that already holds the keys listed in secret_values."
  type        = string
  default     = ""
}

variable "create_dev_secret" {
  description = "development profile only: let the chart generate throw-away secrets."
  type        = bool
  default     = false
}

variable "values" {
  description = "Extra chart values (merged over the ones this module sets), as a YAML string."
  type        = string
  default     = ""
}

variable "monitoring" {
  description = "Create the ServiceMonitor and PrometheusRule (needs the Prometheus Operator CRDs)."
  type        = bool
  default     = false
}

variable "timeout_seconds" {
  type    = number
  default = 600
}
