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
	fi
fi

if [ -d "$UPSTART" ]; then
	if [ -f "/etc/init/tyk-gateway.conf" ]
	then
		echo "Found upstart"
		rm /etc/init/tyk-gateway.conf 
	fi
fi

if [ -d "$SYSV1" ]; then
	if [ -f "/etc/default/tyk-gateway" ]
	then
		echo "Found SysV1"
		rm /etc/default/tyk-gateway
	fi

	if [ -f "/etc/init.d/tyk-gateway" ]
	then
		rm /etc/init.d/tyk-gateway
	fi  	
fi

if [ -d "$SYSV2" ]; then
	if [ -f "/etc/rc.d/init.d/tyk-gateway" ]
	then
		echo "Found Sysv2"
		rm /etc/rc.d/init.d/tyk-gateway
	fi  
	
fi