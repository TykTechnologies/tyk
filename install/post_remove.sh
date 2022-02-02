#!/bin/bash
echo "Removing init scripts..."

SYSTEMD="/lib/systemd/system"
UPSTART="/etc/init"
SYSV1="/etc/init.d"
SYSV2="/etc/rc.d/init.d/"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -f "/lib/systemd/system/tyk-gateway.service" ]; then
	echo "Found Systemd"
	echo "Stopping the service"
	systemctl stop tyk-gateway.service
        # Removed lua and python in 2.9, keeping so upgrades work
        # and for compatibility.
	systemctl stop tyk-gateway-python.service || true
	echo "Removing the service"
	rm -f /lib/systemd/system/tyk-gateway.service
	rm -f /lib/systemd/system/tyk-gateway-python.service
	systemctl --system daemon-reload
fi

if [ -f "/etc/init/tyk-gateway.conf" ]; then
	echo "Found upstart"
	echo "Stopping the service"
	stop tyk-gateway
	stop tyk-gateway-python || true
	echo "Removing the service"
	rm -f /etc/init/tyk-gateway.conf
	rm -f /etc/init/tyk-gateway-python.conf
fi

if [ -f "/etc/init.d/tyk-gateway" ]; then
	echo "Found Sysv1"
	/etc/init.d/tyk-gateway stop
	/etc/init.d/tyk-gateway-python stop || true
	rm -f /etc/init.d/tyk-gateway
	rm -f /etc/init.d/tyk-gateway-python
fi

if [ -f "/etc/rc.d/init.d/tyk-gateway" ]; then
	echo "Found Sysv2"
	echo "Stopping the service"
	/etc/rc.d/init.d/tyk-gateway stop
	/etc/rc.d/init.d/tyk-gateway-python stop || true
	echo "Removing the service"
	rm -f /etc/rc.d/init.d/tyk-gateway
	rm -f /etc/rc.d/init.d/tyk-gateway-python
fi
