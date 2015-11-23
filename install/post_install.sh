#!/bin/bash
echo "Installing init scripts..."

SYSTEMD="/lib/systemd/system"
UPSTART="/etc/init"
SYSV1="/etc/init.d"
SYSV2="/etc/rc.d/init.d/"
DIR="/opt/tyk-gateway/install"

if [ -d "$SYSTEMD" ]; then
	echo "Found Systemd"
	cp $DIR/inits/systemd/system/tyk-gateway.service /lib/systemd/system/tyk-gateway.service
fi

if [ -d "$UPSTART" ]; then
	echo "Found upstart"
	cp $DIR/inits/upstart/conf/tyk-gateway.conf /etc/init/
fi

if [ -d "$SYSV1" ]; then
	echo "Found SysV1"
	cp $DIR/inits/sysv/etc/default/tyk-gateway /etc/default/tyk-gateway
	cp $DIR/inits/sysv/etc/init.d/tyk-gateway /etc/init.d/tyk-gateway
  	
fi

if [ -d "$SYSV2" ]; then
	echo "Found Sysv2"
  	cp $DIR/inits/sysv/etc/default/tyk-gateway /etc/default/tyk-gateway
	cp $DIR/inits/sysv/etc/init.d/tyk-gateway /etc/rc.d/init.d/tyk-gateway
fi