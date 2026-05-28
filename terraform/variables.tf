variable "project_id" {
  type        = string
  description = "The GCP Project ID where resources will be deployed."
}

variable "region" {
  type        = string
  description = "The target GCP Region."
  default     = "us-central1"
}

variable "prefix" {
  type        = string
  description = "Naming prefix applied to all resources."
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
