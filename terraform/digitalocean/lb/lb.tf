provider "digitalocean" {
  token = "${var.do_token}"
}

resource "digitalocean_loadbalancer" "gateway" {
  "forwarding_rule" {
    entry_port = 0
    entry_protocol = ""
    target_port = 0
    target_protocol = ""
  }
  name = ""
  region = ""
}
