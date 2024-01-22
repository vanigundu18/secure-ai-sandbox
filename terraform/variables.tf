variable "project_id" {
  type        = string
  description = "The GCP Project ID where all resources will be deployed."
}

variable "region" {
  type        = string
  description = "Target GCP region for all regional resources."
  default     = "us-central1"
}

variable "prefix" {
  type        = string
  description = "Naming prefix applied to every resource. Keep short (≤ 20 chars)."
  default     = "secure-ai-sandbox"
}

variable "k8s_namespace" {
  type        = string
  description = "Kubernetes Namespace where the Gateway service runs."
  default     = "ai-gateway"
}

variable "k8s_service_account" {
  type        = string
  description = "Kubernetes Service Account name assigned to the Gateway Pod."
  default     = "guardrail-gateway-sa"
}

variable "admin_cidr" {
  type        = string
  description = "CIDR block allowed to reach the GKE API server endpoint. Restrict to your VPN/bastion range."
  default     = "0.0.0.0/0" # TODO: restrict before production
}

variable "deletion_protection" {
  type        = bool
  description = "Set to false only when you intend to permanently destroy the GKE cluster."
  default     = true
}

variable "artifact_registry_region" {
  type        = string
  description = "Region for Artifact Registry Docker repository."
  default     = "us-central1"
}
