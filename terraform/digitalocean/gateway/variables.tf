variable "do_token" {}

variable "ssh_fingerprint" {}

variable "key_path" {}

variable "region" {}

variable "num_instances" {
  default = 1
}

variable "tag" {}

variable "size" {}

variable "centos" {
  description = "Default Centos"
  default     = "centos-7-x64"
}

variable "redis_server" {}
