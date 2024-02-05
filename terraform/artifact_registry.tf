# ==============================================================================
# ARTIFACT REGISTRY
# Private Docker repository for storing hardened gateway container images.
# Images are scanned automatically by Container Analysis on push.
# ==============================================================================

resource "google_artifact_registry_repository" "gateway_registry" {
  location      = var.artifact_registry_region
  repository_id = "${var.prefix}-registry"
  description   = "Private Docker registry for Guardrail Gateway images"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-last-10-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-untagged-after-14d"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "1209600s" # 14 days
    }
  }
}

# Grant the gateway GSA read access to pull its own images
resource "google_artifact_registry_repository_iam_member" "gateway_registry_reader" {
  location   = google_artifact_registry_repository.gateway_registry.location
  repository = google_artifact_registry_repository.gateway_registry.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.gateway_gsa.email}"
}

# Grant Cloud Build write access to push images during CI
resource "google_artifact_registry_repository_iam_member" "cloudbuild_registry_writer" {
  location   = google_artifact_registry_repository.gateway_registry.location
  repository = google_artifact_registry_repository.gateway_registry.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

data "google_project" "project" {
  project_id = var.project_id
}
