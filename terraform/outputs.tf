output "vpc_id" {
  value       = google_compute_network.sandbox_vpc.id
  description = "The ID of the generated Private VPC Network."
}

output "subnet_id" {
  value       = google_compute_subnetwork.gke_subnet.id
  description = "The ID of the GKE Node subnet."
}

output "gke_cluster_endpoint" {
  value       = google_container_cluster.secure_cluster.endpoint
  description = "The Control Plane endpoint URI of the GKE Autopilot Cluster."
}

output "gateway_sa_email" {
  value       = google_service_account.gateway_gsa.email
  description = "The email address of the hardened Google Service Account."
}

output "workload_identity_member" {
  value       = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account}]"
  description = "The Workload Identity member mapping for Kubernetes RBAC binding."
}
