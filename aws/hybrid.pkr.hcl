variable "aws_access_key" {
  type    = string
  default = "${env("AWS_ACCESS_KEY_ID")}"
}

variable "aws_secret_key" {
  type    = string
  default = "${env("AWS_SECRET_ACCESS_KEY")}"
}

variable "geoip_license" {
  type    = string
  default = "${env("GEOIP_LICENSE")}"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "tyk_gw_version" {
  type    = string
  default = "${env("TYK_GATEWAY_VERSION")}"
}

# "timestamp" template function replacement
locals { timestamp = regex_replace(timestamp(), "[- TZ:]", "") }

# source blocks are generated from your builders; a source can be referenced in
# build blocks. A build block runs provisioner and post-processors on a
# source. Read the documentation for source blocks here:
# https://www.packer.io/docs/from-1.5/blocks/source
# template: hcl2_upgrade:4:95: executing "hcl2_upgrade" at <clean_resource_name>: error calling clean_resource_name: unhandled "clean_resource_name" call:
# there is no way to automatically upgrade the "clean_resource_name" call.
# Please manually upgrade to use custom validation rules, `replace(string, substring, replacement)` or `regex_replace(string, substring, replacement)`
# Visit https://packer.io/docs/from-1.5/variables#custom-validation-rules , https://www.packer.io/docs/from-1.5/functions/string/replace or https://www.packer.io/docs/from-1.5/functions/string/regex_replace for more infos.

source "amazon-ebs" "Gateway" {
  access_key    = "{{user `aws_access_key`}}"
  ami_name      = "Tyk API Gateway v{{user `tyk_gw_version`}} ({{user `flavour`}}) {{isotime | clean_resource_name}}"
  ena_support   = true
  instance_type = "t3.micro"
  region        = "{{user `region`}}"
  secret_key    = "{{user `aws_secret_key`}}"
  source_ami    = "{{user `source_ami`}}"
  source_ami_filter {
    filters = {
      architecture                       = "x86_64"
      "block-device-mapping.volume-type" = "gp2"
      name                               = "{{user `ami_search_string`}}"
      root-device-type                   = "ebs"
      sriov-net-support                  = "simple"
      virtualization-type                = "hvm"
    }
    most_recent = true
    owners      = ["{{user `source_ami_owner`}}"]
  }
  sriov_support = true
  ssh_username  = "ec2-user"
  subnet_filter {
    filters = {
      "tag:Class" = "build"
    }
    most_free = true
    random    = false
  }
  tags = {
    Component = "gateway"
    Flavour   = "{{user `flavour`}}"
    Product   = "Standalone"
  }
}

# a build block invokes sources and runs provisioning steps on them. The
# documentation for build blocks can be found here:
# https://www.packer.io/docs/from-1.5/blocks/build
build {
  sources = ["source.amazon-ebs.Gateway"]

  provisioner "file" {
    destination = "/tmp/tyk_hybrid.conf"
    source      = "./hybrid/tyk_hybrid.conf"
  }
  provisioner "file" {
    destination = "/tmp/setup_hybrid.sh"
    source      = "./hybrid/setup_hybrid.sh"
  }
  provisioner "file" {
    destination = "/tmp/semver.sh"
    source      = "./semver.sh"
  }
  provisioner "file" {
    destination = "/tmp/10-run-tyk.conf"
    source      = "./10-run-tyk.conf"
  }
  provisioner "shell" {
    environment_vars = ["TYK_GATEWAY_VERSION=${var.tyk_gw_version}", "GEOIP_LICENSE=${var.geoip_license}"]
    script           = "hybrid/install-gateway.sh"
  }
  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
