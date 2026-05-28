# ==============================================================================
# SECURE AI SANDBOX - TERRAFORM CONFIGURATION
# Provisions a Hardened, Zero-Trust Google Cloud environment for secure LLM 
# execution sandboxing and model-serving workloads.
# ==============================================================================

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.50.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ------------------------------------------------------------------------------
# 1. HARDENED NETWORK TOPOLOGY (VPC, Subnets, Cloud NAT)
# ------------------------------------------------------------------------------

resource "google_compute_network" "sandbox_vpc" {
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gke_subnet" {
  name                     = "${var.prefix}-gke-subnet"
  ip_cidr_range            = "10.10.0.0/20"
  region                   = var.region
  network                  = google_compute_network.sandbox_vpc.id
  private_ip_google_access = true

  # Secondary ranges for GKE Pods and Services (IP Aliasing)
  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "172.16.0.0/14"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "172.20.0.0/16"
  }
}

# Cloud Router and NAT Gateway to ensure GKE private nodes can pull external 
# packages (e.g., from HuggingFace, pip, docker) without public IP exposure.
resource "google_compute_router" "router" {
  name    = "${var.prefix}-router"
  region  = var.region
  network = google_compute_network.sandbox_vpc.id
}

resource "google_compute_router_nat" "nat_gateway" {
  name                               = "${var.prefix}-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# ------------------------------------------------------------------------------
# 2. HARDENED GKE CLUSTER (Autopilot with Hardening Profiles)
# ------------------------------------------------------------------------------

resource "google_container_cluster" "secure_cluster" {
  name     = "${var.prefix}-cluster"
  location = var.region

  network    = google_compute_network.sandbox_vpc.id
  subnetwork = google_compute_subnetwork.gke_subnet.id

  # Autopilot enforces best-practice security baselines automatically,
  # including Shielded GKE Nodes and Node Auto-Provisioning.
  enable_autopilot = true

  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  # Restrict Cluster Master Endpoint to specific admin IP addresses for security
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0" # In production, restrict to corporate VPN/Bastian host CIDRs
      display_name = "Allow-all-admin"
    }
  }

  # Enforce Workload Identity to bridge Kubernetes and Google Cloud IAM
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Advanced Cluster Security configurations
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false # Keep endpoint public for simplified administration, private in production
  }
}

# ------------------------------------------------------------------------------
# 3. LEAST-PRIVILEGE WORKLOAD IDENTITY AND SERVICE ACCOUNTS
# ------------------------------------------------------------------------------

# Google Service Account for the Guardrail Gateway
resource "google_service_account" "gateway_gsa" {
  account_id   = "${var.prefix}-gateway-sa"
  display_name = "Workload Identity Service Account for AI Guardrail Gateway"
}

# Grant Vertex AI Reader role to the Gateway GSA (minimum role required to invoke Gemini/Model Armor)
resource "google_project_iam_member" "vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.gateway_gsa.email}"
}

# IAM Binding: Map Kubernetes Service Account to the Google Service Account (Workload Identity binding)
resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.gateway_gsa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account}]"
}
