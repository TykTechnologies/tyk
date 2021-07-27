#!/bin/sh

SERVICE_NAME=tyk-gateway

if command -V systemctl >/dev/null 2>&1; then
    if [ ! -f /lib/systemd/system/${SERVICE_NAME}.service ]; then
	cp /opt/${SERVICE_NAME}/install/${SERVICE_NAME}.service /lib/systemd/system/${SERVICE_NAME}.service
	echo Restored systemd service file
    fi
fi
