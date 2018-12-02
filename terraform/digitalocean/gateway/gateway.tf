provider "digitalocean" {
  token = "${var.do_token}"
}

resource "digitalocean_droplet" "tyk-gateway" {
  count = "${var.num_instances}"
  image = "${var.centos}"
  name = "tyk-gateway-${count.index + 1}"
  region = "${var.region}"
  size = "${var.size}"
  tags = ["${var.tag}"]
  private_networking = true

  ssh_keys = ["${var.ssh_fingerprint}"]

  connection {
    type = "ssh"
    private_key = "${file("${var.key_path}")}"
    user = "root"
    timeout = "10m"
  }

  provisioner "file" {
    source = "${path.module}/../../shared/tyk-gateway.repo"
    destination = "/etc/yum.repos.d/tyk_tyk-gateway.repo"
  }

  provisioner "file" {
    source = "${path.module}/../../shared/rc.local"
    destination = "/tmp/rc.local"
  }

  provisioner "file" {
    source = "${path.module}/../../shared/limits.conf"
    destination = "/tmp/limits.conf"
  }

  provisioner "remote-exec" {
    inline = [
      // add redis host to system env vars
      "echo 'TYK_GW_STORAGE_HOST=${var.redis_server}' >> /etc/default/tyk-gateway",
      "cat /tmp/rc.local >> /etc/rc.d/rc.local",
      "chmod +x /etc/rc.d/rc.local",
      "systemctl enable rc-local",
      "cat /tmp/limits.conf >> /etc/security/limits.conf",
      "yum -q makecache -y --disablerepo='*' --enablerepo='tyk-gateway'",
      "yum install tyk-gateway -y",
      "systemctl enable tyk-gateway",
      "systemctl start tyk-gateway",
      "reboot &",
    ]
  }
}
