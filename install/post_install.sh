#!/bin/bash
echo "Setting permissions"
# Config file must not be world-readable due to sensitive data
chown tyk:tyk /opt/tyk-gateway/tyk.conf
chmod 660 /opt/tyk-gateway/tyk.conf

echo "Creating a PID directory"
if [ ! -d /var/run/tyk ]; then
	mkdir -p /var/run/tyk
	chown tyk:tyk /var/run/tyk
	chmod 770 /var/run/tyk
fi

echo "Installing init scripts..."

SYSTEMD="/lib/systemd/system"
UPSTART="/etc/init"
SYSV1="/etc/init.d"
SYSV2="/etc/rc.d/init.d/"
DIR="/opt/tyk-gateway/install"

if [ -d "$SYSTEMD" -a -x "$(command -v systemctl)" ]; then
	echo "Found Systemd"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/systemd/default/tyk-gateway /etc/default/
	cp $DIR/inits/systemd/system/tyk-gateway.service /lib/systemd/system/
	cp $DIR/inits/systemd/system/tyk-gateway-lua.service /lib/systemd/system/tyk-gateway-lua.service
	cp $DIR/inits/systemd/system/tyk-gateway-python.service /lib/systemd/system/tyk-gateway-python.service
	systemctl --system daemon-reload
	exit
fi

if [ -d "$UPSTART" ]; then
	echo "Found upstart"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/upstart/default/tyk-gateway /etc/default/
	cp $DIR/inits/upstart/init/tyk-gateway.conf /etc/init/
	cp $DIR/inits/upstart/init/tyk-gateway-lua.conf /etc/init/
	cp $DIR/inits/upstart/init/tyk-gateway-python.conf /etc/init/
	exit
fi

if [ -d "$SYSV1" ]; then
	echo "Found SysV1"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/sysv/default/tyk-gateway /etc/default/
	[ -f /etc/default/tyk-gateway-python ] || cp $DIR/inits/sysv/default/tyk-gateway-python /etc/default/
	[ -f /etc/default/tyk-gateway-lua ] || cp $DIR/inits/sysv/default/tyk-gateway-lua /etc/default/
	cp $DIR/inits/sysv/init.d/tyk-gateway /etc/init.d/tyk-gateway
	cp $DIR/inits/sysv/init.d/tyk-gateway-lua /etc/init.d/tyk-gateway-lua
	cp $DIR/inits/sysv/init.d/tyk-gateway-python /etc/init.d/tyk-gateway-python
	exit
fi

if [ -d "$SYSV2" ]; then
	echo "Found Sysv2"
	[ -f /etc/default/tyk-gateway ] || cp $DIR/inits/sysv/default/tyk-gateway /etc/default/
	[ -f /etc/default/tyk-gateway-python ] || cp $DIR/inits/sysv/default/tyk-gateway-python /etc/default/
	[ -f /etc/default/tyk-gateway-lua ] || cp $DIR/inits/sysv/default/tyk-gateway-lua /etc/default/
	cp $DIR/inits/sysv/init.d/tyk-gateway /etc/rc.d/init.d/tyk-gateway
	cp $DIR/inits/sysv/init.d/tyk-gateway-lua /etc/rc.d/init.d/tyk-gateway-lua
	cp $DIR/inits/sysv/init.d/tyk-gateway-python /etc/rc.d/init.d/tyk-gateway-python
	exit
fi
