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
	systemctl stop tyk-gateway-python.service
	systemctl stop tyk-gateway-lua.service
	echo "Removing the service"
	rm /lib/systemd/system/tyk-gateway.service
	rm /lib/systemd/system/tyk-gateway-python.service
	rm /lib/systemd/system/tyk-gateway-lua.service
	systemctl --system daemon-reload
fi

if [ -f "/etc/init/tyk-gateway.conf" ]; then
	echo "Found upstart"
	echo "Stopping the service"
	service tyk-gateway stop
	service tyk-gateway-python stop
	service tyk-gateway-lua stop
	echo "Removing the service"
	rm /etc/init/tyk-gateway.conf
	rm /etc/init/tyk-gateway-python.conf
	rm /etc/init/tyk-gateway-lua.conf
fi

if [ -f "/etc/init.d/tyk-gateway" ]; then
	echo "Found Sysv1"
	/etc/init.d/tyk-gateway stop
	/etc/init.d/tyk-gateway-python stop
	/etc/init.d/tyk-gateway-lua stop
	rm /etc/init.d/tyk-gateway
	rm /etc/init.d/tyk-gateway-python
	rm /etc/init.d/tyk-gateway-lua
fi

if [ -f "/etc/rc.d/init.d/tyk-gateway" ]; then
	echo "Found Sysv2"
	echo "Stopping the service"
	/etc/rc.d/init.d/tyk-gateway stop
	/etc/rc.d/init.d/tyk-gateway-python stop
	/etc/rc.d/init.d/tyk-gateway-lua stop
	echo "Removing the service"
	rm /etc/rc.d/init.d/tyk-gateway
	rm /etc/rc.d/init.d/tyk-gateway-python
	rm /etc/rc.d/init.d/tyk-gateway-lua
fi
