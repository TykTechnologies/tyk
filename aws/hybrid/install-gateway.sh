#!/bin/bash
set -ex

# 2.9.3.x do not follow semver and semver.sh will barf
if [[ $TYK_GATEWAY_VERSION =~ 2.9.[34].[[:digit:]] ]]; then
    gwlt29="1"
else
    # Python 3.4 is needed upto 2.8.x, later versions can use the latest Python
    printf -v gwlt29 $(/tmp/semver.sh compare $TYK_GATEWAY_VERSION 2.9.0)
fi

if [[ $gwlt29 == "-1" ]]; then
    python_pkgs="python34-libs python34-pip python34-devel"
    pip=pip3.4
    grpcio="grpcio==1.7.0"
else
    python_pkgs="python3-libs python3-pip python3-devel"
    pip=pip3
    grpcio="grpcio"
fi

sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E '%{rhel}').noarch.rpm
sudo yum update -y
curl -s https://packagecloud.io/install/repositories/tyk/tyk-gateway/script.rpm.sh | sudo bash

# Newest grpc requires g++
sudo yum install -y tyk-gateway-${TYK_GATEWAY_VERSION} gcc gcc-c++ awslogs $python_pkgs
sudo amazon-linux-extras install redis4.0

#sudo yum install -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm || true

mkdir geolite && cd geolite
curl "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${GEOIP_LICENSE}&suffix=tar.gz" -o GeoLite2-City.tar.gz
tar xzf GeoLite2-City.tar.gz --strip=1
sudo mv -v GeoLite2-City.mmdb /opt/tyk-gateway
sudo mv -v LICENSE.txt /opt/tyk-gateway/GeoLite2-City.LICENSE
cd && rm -rf geolite

sudo $pip install $grpcio protobuf

# Disable redis, will be enabled by setup_hybrid.sh if needed
sudo systemctl stop redis || true
sudo systemctl disable redis

# Move scripts from ephemeral /tmp
sudo mv /tmp/setup_hybrid.sh /tmp/tyk_hybrid.conf /opt/tyk-gateway

# Confine tyk to its own user (should eventually be done by the package)	
sudo mkdir -p /etc/systemd/system/tyk-gateway.service.d
sudo mv /tmp/10-run-tyk.conf /etc/systemd/system/tyk-gateway.service.d
sudo chown -R tyk:tyk /opt/tyk-gateway	
sudo chmod 660 /opt/tyk-gateway/tyk.conf	
sudo mkdir -p /var/run/tyk && sudo chown tyk:tyk /var/run/tyk && sudo chmod 770 /var/run/tyk

sudo systemctl disable tyk-gateway tyk-gateway-python

sudo rm -f /home/ec2-user/.ssh/authorized_keys
sudo rm -f /root/.ssh/authorized_keys
