#!/bin/bash
echo "Removing init scripts..."

SYSTEMD="/lib/systemd/system"
UPSTART="/etc/init"
SYSV1="/etc/init.d"
SYSV2="/etc/rc.d/init.d/"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -d "$SYSTEMD" ]; then
	if [ -f "/lib/systemd/system/tyk-gateway.service" ]
	then
		echo "Found Systemd"
		rm /lib/systemd/system/tyk-gateway.service
		rm /lib/systemd/system/tyk-gateway-lua.service
		rm /lib/systemd/system/tyk-gateway-python.service
	fi
fi

if [ -d "$UPSTART" ]; then
	if [ -f "/etc/init/tyk-gateway.conf" ]
	then
		echo "Found upstart"
		rm /etc/init/tyk-gateway.conf 
		rm /etc/init/tyk-gateway-lua.conf 
		rm /etc/init/tyk-gateway-python.conf 
	fi
fi

if [ -d "$SYSV1" ]; then
	if [ -f "/etc/default/tyk-gateway" ]
	then
		echo "Found SysV1"
		rm /etc/default/tyk-gateway
		rm /etc/default/tyk-gateway-lua
		rm /etc/default/tyk-gateway-python
	fi

	if [ -f "/etc/init.d/tyk-gateway" ]
	then
		rm /etc/init.d/tyk-gateway
		rm /etc/init.d/tyk-gateway-lua
		rm /etc/init.d/tyk-gateway-python
	fi  	
fi

if [ -d "$SYSV2" ]; then
	if [ -f "/etc/rc.d/init.d/tyk-gateway" ]
	then
		echo "Found Sysv2"
		rm /etc/rc.d/init.d/tyk-gateway
		rm /etc/rc.d/init.d/tyk-gateway-lua
		rm /etc/rc.d/init.d/tyk-gateway-python
	fi  
	
fi