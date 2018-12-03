module "redis" {
  source = "./digitalocean/redis"
  ssh_fingerprint = "${var.ssh_fingerprint}"
  region = "${var.region}"
  size = "${var.size}"
  tag = "${var.tag}"
  do_token = "${var.do_token}"
  key_path = "${var.key_path}"
}

resource "random_string" "gateway-secret" {
  length = 32
  special = false
}

module "gateway" {
  source = "./digitalocean/gateway"
  redis_server = "${module.redis.local_ip}"
  ssh_fingerprint = "${var.ssh_fingerprint}"
  num_instances = "${var.num_instances}"
  region = "${var.region}"
  size = "${var.size}"
  tag = "${var.tag}"
  do_token = "${var.do_token}"
  key_path = "${var.key_path}"
  secret = "${random_string.gateway-secret.result}"
}

variable "ssh_fingerprint" {}

variable "region" {}

variable "size" {}

variable "tag" {}

variable "do_token" {}

variable "key_path" {}

variable "num_instances" {}
