provider "digitalocean" {
  token = "${var.do_token}"
}

resource "digitalocean_droplet" "tyk-redis" {
  image = "${var.centos}"
  name = "tyk-redis"
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
    source = "${path.module}/../../shared/rc.local"
    destination = "/tmp/rc.local"
  }

  provisioner "file" {
    source = "${path.module}/../../shared/limits.conf"
    destination = "/tmp/limits.conf"
  }

  provisioner "remote-exec" {
    inline = [
      "cat /tmp/rc.local >> /etc/rc.d/rc.local",
      "chmod +x /etc/rc.d/rc.local",
      "systemctl enable rc-local",
      "cat /tmp/limits.conf >> /etc/security/limits.conf",
      "yum install epel-release -y",
      "yum install redis -y",
      "sed -i 's/^bind 127.0.0.1/bind ${digitalocean_droplet.tyk-redis.ipv4_address_private}/' /etc/redis.conf",
      "systemctl enable redis",
      "systemctl start redis",
      "reboot &",
    ]
  }
}

output "local_ip" {
  value = "${digitalocean_droplet.tyk-redis.ipv4_address_private}"
}
