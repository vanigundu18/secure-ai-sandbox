output "vpc_id" {
  value       = google_compute_network.sandbox_vpc.id
  description = "Self-link of the private VPC network."
}

output "subnet_id" {
  value       = google_compute_subnetwork.gke_subnet.id
  description = "Self-link of the GKE node subnet."
}

output "gke_cluster_name" {
  value       = google_container_cluster.secure_cluster.name
  description = "Name of the GKE Autopilot cluster."
}

output "gke_cluster_endpoint" {
  value       = google_container_cluster.secure_cluster.endpoint
  description = "GKE API server endpoint — use with kubectl get-credentials."
  sensitive   = true
}

output "gateway_sa_email" {
  value       = google_service_account.gateway_gsa.email
  description = "Email of the least-privilege Gateway Google Service Account."
}

output "workload_identity_member" {
  value       = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account}]"
  description = "Full Workload Identity member string for IAM policy bindings."
}

output "artifact_registry_url" {
  value       = "${var.artifact_registry_region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.gateway_registry.repository_id}"
  description = "Base URL for the Docker Artifact Registry — use as image prefix."
}

output "kubectl_config_command" {
  value       = "gcloud container clusters get-credentials ${google_container_cluster.secure_cluster.name} --region ${var.region} --project ${var.project_id}"
  description = "One-liner to configure kubectl for this cluster."
}
