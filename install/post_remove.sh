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
	systemctl stop tyk-gateway-lua.service || true
	echo "Removing the service"
	rm -f /lib/systemd/system/tyk-gateway.service
	rm -f /lib/systemd/system/tyk-gateway-python.service
	rm -f /lib/systemd/system/tyk-gateway-lua.service
	systemctl --system daemon-reload
fi

if [ -f "/etc/init/tyk-gateway.conf" ]; then
	echo "Found upstart"
	echo "Stopping the service"
	service tyk-gateway stop
	service tyk-gateway-python stop || true
	srevice tyk-gateway-lua stop || true
	echo "Removing the service"
	rm -f /etc/init/tyk-gateway.conf
	rm -f /etc/init/tyk-gateway-python.conf
	rm -f /etc/init/tyk-gateway-lua.conf
fi

if [ -f "/etc/init.d/tyk-gateway" ]; then
	echo "Found Sysv1"
	/etc/init.d/tyk-gateway stop
	/etc/init.d/tyk-gateway-python stop || true
	/etc/init.d/tyk-gateway-lua stop || true
	rm -f /etc/init.d/tyk-gateway
	rm -f /etc/init.d/tyk-gateway-python
	rm -f /etc/init.d/tyk-gateway-lua
fi

if [ -f "/etc/rc.d/init.d/tyk-gateway" ]; then
	echo "Found Sysv2"
	echo "Stopping the service"
	/etc/rc.d/init.d/tyk-gateway stop
	/etc/rc.d/init.d/tyk-gateway-python stop || true
	/etc/rc.d/init.d/tyk-gateway-lua stop || true
	echo "Removing the service"
	rm -f /etc/rc.d/init.d/tyk-gateway
	rm -f /etc/rc.d/init.d/tyk-gateway-python
	rm -f /etc/rc.d/init.d/tyk-gateway-lua
fi
