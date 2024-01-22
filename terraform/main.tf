# ==============================================================================
# SECURE AI SANDBOX — TERRAFORM CONFIGURATION
# Provisions a hardened, zero-trust Google Cloud environment for secure LLM
# execution sandboxing and model-serving workloads.
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 6.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }

  # Uncomment and configure for remote state management
  # backend "gcs" {
  #   bucket = "YOUR_TF_STATE_BUCKET"
  #   prefix = "secure-ai-sandbox/state"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ==============================================================================
# 1. HARDENED NETWORK TOPOLOGY
# ==============================================================================

resource "google_compute_network" "sandbox_vpc" {
  name                            = "${var.prefix}-vpc"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = true
}

# Default internet route — required for Cloud NAT egress
resource "google_compute_route" "default_egress" {
  name             = "${var.prefix}-default-egress"
  network          = google_compute_network.sandbox_vpc.id
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
}

resource "google_compute_subnetwork" "gke_subnet" {
  name                     = "${var.prefix}-gke-subnet"
  ip_cidr_range            = "10.10.0.0/20"
  region                   = var.region
  network                  = google_compute_network.sandbox_vpc.id
  private_ip_google_access = true

  # Secondary ranges required for GKE VPC-native networking
  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "172.16.0.0/14"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "172.20.0.0/16"
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Cloud Router and NAT Gateway — allows private GKE nodes to pull images
# without requiring public IP addresses on nodes.
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

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall: deny all ingress by default (explicit allow below)
resource "google_compute_firewall" "deny_all_ingress" {
  name      = "${var.prefix}-deny-all-ingress"
  network   = google_compute_network.sandbox_vpc.id
  direction = "INGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# Firewall: allow GKE control-plane to communicate with nodes
resource "google_compute_firewall" "allow_gke_internal" {
  name    = "${var.prefix}-allow-gke-internal"
  network = google_compute_network.sandbox_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["443", "10250"]
  }

  source_ranges = ["10.10.0.0/20"]
  target_tags   = ["gke-node"]
}

# ==============================================================================
# 2. HARDENED GKE AUTOPILOT CLUSTER
# ==============================================================================

resource "google_container_cluster" "secure_cluster" {
  name     = "${var.prefix}-cluster"
  location = var.region

  network    = google_compute_network.sandbox_vpc.id
  subnetwork = google_compute_subnetwork.gke_subnet.id

  # Autopilot enforces security baselines: Shielded GKE Nodes, secure boot,
  # node auto-provisioning with workload isolation.
  enable_autopilot = true

  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  # Restrict API server access — replace 0.0.0.0/0 with corporate VPN/bastion CIDRs
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = var.admin_cidr
      display_name = "admin-access"
    }
  }

  # Workload Identity bridges Kubernetes and Google Cloud IAM without key files
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Private nodes — no public IPs on worker nodes
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.31.0.0/28"
  }

  # Enable Binary Authorization for supply-chain integrity
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  release_channel {
    channel = "REGULAR"
  }

  # Structured audit logging
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  deletion_protection = var.deletion_protection
}

# ==============================================================================
# 3. LEAST-PRIVILEGE WORKLOAD IDENTITY
# ==============================================================================

# Google Service Account for the Guardrail Gateway
resource "google_service_account" "gateway_gsa" {
  account_id   = "${var.prefix}-gateway-sa"
  display_name = "Guardrail Gateway Workload Identity SA"
  description  = "Minimal-privilege service account for the AI Guardrail Gateway pod"
}

# Grant Vertex AI User role — minimum required to call Model Armor / Gemini endpoints
resource "google_project_iam_member" "vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.gateway_gsa.email}"
}

# Grant read-only access to Secret Manager — for Anthropic API key retrieval
resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.gateway_gsa.email}"
}

# Workload Identity binding: Kubernetes SA → Google SA
resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.gateway_gsa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account}]"
}
