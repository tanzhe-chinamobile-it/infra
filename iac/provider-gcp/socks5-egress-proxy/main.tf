# Stable egress IP via isolated VPC + Cloud NAT + auto-healing SOCKS5 proxy.
# Set the "sandbox-egress-proxy" flag to "<lb_ip>:1080" per team.

# --- Isolated VPC ---

resource "google_compute_network" "egress" {
  name                    = "${var.prefix}socks5-egress"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "egress" {
  name          = "${var.prefix}socks5-egress"
  network       = google_compute_network.egress.id
  region        = var.gcp_region
  ip_cidr_range = var.subnet_cidr
}

resource "google_compute_network_peering" "main_to_egress" {
  name         = "${var.prefix}main-to-socks5-egress"
  network      = data.google_compute_network.main.self_link
  peer_network = google_compute_network.egress.self_link
}

resource "google_compute_network_peering" "egress_to_main" {
  name         = "${var.prefix}socks5-egress-to-main"
  network      = google_compute_network.egress.self_link
  peer_network = data.google_compute_network.main.self_link

  depends_on = [google_compute_network_peering.main_to_egress]
}

data "google_compute_network" "main" {
  name = var.main_network_name
}

# --- Static IPs + Cloud NAT ---

resource "google_compute_address" "egress_ip" {
  count        = 3
  name         = "${var.prefix}socks5-egress-ip-${count.index + 1}"
  region       = var.gcp_region
  address_type = "EXTERNAL"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_router" "egress" {
  name    = "${var.prefix}socks5-egress-router"
  network = google_compute_network.egress.id
  region  = var.gcp_region
}

resource "google_compute_router_nat" "egress" {
  name                               = "${var.prefix}socks5-egress-nat"
  router                             = google_compute_router.egress.name
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = google_compute_address.egress_ip[*].self_link
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  min_ports_per_vm                   = 4096

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# --- Firewall (deny-all baseline + explicit allows) ---

resource "google_compute_firewall" "deny_all_ingress" {
  name     = "${var.prefix}socks5-egress-deny-all-ingress"
  network  = google_compute_network.egress.id
  priority = 65534

  deny {
    protocol = "all"
  }

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "deny_all_egress" {
  name     = "${var.prefix}socks5-egress-deny-all-egress"
  network  = google_compute_network.egress.id
  priority = 65534

  deny {
    protocol = "all"
  }

  direction          = "EGRESS"
  destination_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_socks5_from_peered" {
  name    = "${var.prefix}socks5-egress-allow-from-orchestrator"
  network = google_compute_network.egress.id

  allow {
    protocol = "tcp"
    ports    = ["1080"]
  }

  source_ranges = [var.orchestrator_cidr]
  target_tags   = ["socks5-egress-proxy"]
}

resource "google_compute_firewall" "allow_healthcheck" {
  name    = "${var.prefix}socks5-egress-allow-healthcheck"
  network = google_compute_network.egress.id

  allow {
    protocol = "tcp"
    ports    = ["1080"]
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  target_tags   = ["socks5-egress-proxy"]
}

resource "google_compute_firewall" "allow_egress_internet" {
  name    = "${var.prefix}socks5-egress-allow-internet"
  network = google_compute_network.egress.id

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  direction          = "EGRESS"
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["socks5-egress-proxy"]
}

# COS needs to pull the container image from gcr/dockerhub
resource "google_compute_firewall" "allow_egress_gcr" {
  name    = "${var.prefix}socks5-egress-allow-gcr"
  network = google_compute_network.egress.id

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  direction          = "EGRESS"
  destination_ranges = ["199.36.153.4/30"]
  target_tags        = ["socks5-egress-proxy"]
}

# --- Service account (minimal permissions) ---

resource "google_service_account" "socks5_proxy" {
  account_id   = "${var.prefix}socks5-egress-proxy"
  display_name = "SOCKS5 egress proxy"
}

resource "google_project_iam_member" "socks5_proxy_log_writer" {
  project = data.google_project.current.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.socks5_proxy.email}"
}

resource "google_project_iam_member" "socks5_proxy_metric_writer" {
  project = data.google_project.current.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.socks5_proxy.email}"
}

data "google_project" "current" {}

# --- Instance template ---

resource "google_compute_instance_template" "socks5_proxy" {
  name_prefix  = "${var.prefix}socks5-egress-"
  machine_type = var.machine_type
  region       = var.gcp_region
  tags         = ["socks5-egress-proxy"]

  disk {
    source_image = "cos-cloud/cos-stable"
    disk_size_gb = 10
    disk_type    = "pd-ssd"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    subnetwork = google_compute_subnetwork.egress.self_link
  }

  service_account {
    email  = google_service_account.socks5_proxy.email
    scopes = ["logging-write", "monitoring-write"]
  }

  shielded_instance_config {
    enable_secure_boot = true
    enable_vtpm        = true
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "false"
    gce-container-declaration = yamlencode({
      spec = {
        containers = [{
          image = var.socks5_image
          env   = [{ name = "PROXY_PORT", value = "1080" }]
        }]
        restartPolicy = "Always"
      }
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --- Regional MIG + auto-healing + rolling updates ---

resource "google_compute_region_instance_group_manager" "socks5_proxy" {
  name               = "${var.prefix}socks5-egress-proxy"
  base_instance_name = "${var.prefix}socks5-egress"
  region             = var.gcp_region
  target_size        = var.instance_count

  version {
    instance_template = google_compute_instance_template.socks5_proxy.self_link_unique
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.socks5_proxy.id
    initial_delay_sec = 120
  }

  named_port {
    name = "socks5"
    port = 1080
  }
}

resource "google_compute_health_check" "socks5_proxy" {
  name                = "${var.prefix}socks5-egress-hc"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = 1080
  }
}

# --- Internal TCP LB ---

resource "google_compute_region_backend_service" "socks5_proxy" {
  name                  = "${var.prefix}socks5-egress-backend"
  region                = var.gcp_region
  protocol              = "TCP"
  load_balancing_scheme = "INTERNAL"
  health_checks         = [google_compute_health_check.socks5_proxy.id]

  backend {
    group = google_compute_region_instance_group_manager.socks5_proxy.instance_group
  }

  connection_draining_timeout_sec = 30
}

resource "google_compute_forwarding_rule" "socks5_proxy" {
  name                  = "${var.prefix}socks5-egress-fwd"
  region                = var.gcp_region
  load_balancing_scheme = "INTERNAL"
  backend_service       = google_compute_region_backend_service.socks5_proxy.id
  ip_protocol           = "TCP"
  ports                 = ["1080"]
  network               = google_compute_network.egress.id
  subnetwork            = google_compute_subnetwork.egress.id
}

output "egress_ips" {
  description = "Stable public IPs that sandbox egress appears to come from."
  value       = google_compute_address.egress_ip[*].address
}

output "socks5_proxy_addr" {
  description = "Value to set in the sandbox-egress-proxy feature flag."
  value       = "${google_compute_forwarding_rule.socks5_proxy.ip_address}:1080"
}
