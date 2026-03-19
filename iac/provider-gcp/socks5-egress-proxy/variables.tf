variable "prefix" {
  type    = string
  default = ""
}

variable "gcp_region" {
  type = string
}

variable "main_network_name" {
  description = "The main VPC where orchestrator nodes live. Peered to the egress VPC."
  type        = string
}

variable "orchestrator_cidr" {
  description = "CIDR of the orchestrator subnet (for firewall source filtering via peering)."
  type        = string
}

variable "subnet_cidr" {
  description = "CIDR for the egress proxy subnet."
  type        = string
  default     = "10.200.0.0/24"
}

variable "machine_type" {
  type    = string
  default = "e2-small"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "socks5_image" {
  description = "Container image for the SOCKS5 proxy. Pin to a digest for reproducibility."
  type        = string
  default     = "serjs/go-socks5-proxy:v1.0.3"
}
