#!/bin/bash
set -ex

# Do this first else it will overwrite the change from yum-config-manager 
sudo yum update -y

python_pkgs="python3-libs python3-pip python3-devel"

pip='pip3 install --only-binary ":all:" grpcio protobuf'

# RHEL 7.7 onwards has its own Python3 that interferes with EPEL's Python
source /etc/os-release
if [[ $ID == 'rhel' ]]; then
    sudo yum-config-manager --enable rhel-server-rhui-rhscl-$(rpm -E '%{rhel}')-rpms
    python_pkgs='rh-python36'
    cat > /tmp/pip <<EOF
scl enable rh-python36 'pip install --only-binary ":all:" grpcio protobuf'
EOF
    chmod +x /tmp/pip
    pip='/tmp/pip'
fi

sudo yum install -y gcc gcc-c++ awslogs $python_pkgs
sudo rpm -ih /tmp/tyk-gateway.rpm
sudo $pip

mkdir geolite && cd geolite
curl "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${GEOIP_LICENSE}&suffix=tar.gz" -o GeoLite2-City.tar.gz
tar xzf GeoLite2-City.tar.gz --strip=1
sudo mv -v GeoLite2-City.mmdb /opt/tyk-gateway
sudo mv -v LICENSE.txt /opt/tyk-gateway/GeoLite2-City.LICENSE
cd && rm -rf geolite

sudo rm -f /home/ec2-user/.ssh/authorized_keys
sudo rm -f /root/.ssh/authorized_keys
