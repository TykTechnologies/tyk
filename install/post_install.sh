#!/bin/bash
echo "Installing init scripts..."

SYSTEMD="/lib/systemd/system"
UPSTART="/etc/init"
SYSV1="/etc/init.d"
SYSV2="/etc/rc.d/init.d/"
DIR="/opt/tyk-gateway/install"

if [ -d "$SYSTEMD" ] && systemctl status > /dev/null 2> /dev/null; then
	echo "Found Systemd"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/systemd/default/tyk-gateway /etc/default/
	cp $DIR/inits/systemd/system/tyk-gateway.service /lib/systemd/system/
	cp $DIR/inits/systemd/system/tyk-gateway-python.service /lib/systemd/system/tyk-gateway-python.service
	systemctl --system daemon-reload
	exit
fi

if [ -d "$UPSTART" ]; then
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/upstart/default/tyk-gateway /etc/default/
	if [[ "$(initctl version)" =~ .*upstart[[:space:]]1\..* ]]; then
		echo "Found upstart 1.x+"
		cp $DIR/inits/upstart/init/1.x/tyk-gateway.conf /etc/init/
		cp $DIR/inits/upstart/init/1.x/tyk-gateway-python.conf /etc/init/
	else
		echo "Found upstart 0.x"
		cp $DIR/inits/upstart/init/0.x/tyk-gateway.conf /etc/init/
		cp $DIR/inits/upstart/init/0.x/tyk-gateway-python.conf /etc/init/
	fi
	exit
fi

if [ -d "$SYSV1" ]; then
	echo "Found SysV1"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/sysv/default/tyk-gateway /etc/default/
	[ -f /etc/default/tyk-gateway-python ] || cp $DIR/inits/sysv/default/tyk-gateway-python /etc/default/
	cp $DIR/inits/sysv/init.d/tyk-gateway /etc/init.d/tyk-gateway
	cp $DIR/inits/sysv/init.d/tyk-gateway-python /etc/init.d/tyk-gateway-python
	exit
fi

if [ -d "$SYSV2" ]; then
	echo "Found Sysv2"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/sysv/default/tyk-gateway /etc/default/
	[ -f /etc/default/tyk-gateway-python ] || cp $DIR/inits/sysv/default/tyk-gateway-python /etc/default/
	cp $DIR/inits/sysv/init.d/tyk-gateway /etc/rc.d/init.d/tyk-gateway
	cp $DIR/inits/sysv/init.d/tyk-gateway-python /etc/rc.d/init.d/tyk-gateway-python
	exit
fi
