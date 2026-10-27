output "release_name" {
  value = helm_release.qodiqa.name
}

output "namespace" {
  value = var.namespace
}

output "service" {
  description = "In-cluster service name of the gateway."
  value       = "${helm_release.qodiqa.name}-qodiqa"
}

output "status" {
  value = helm_release.qodiqa.status
}
