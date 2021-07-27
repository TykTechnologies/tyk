#!/bin/sh

SERVICE_NAME=tyk-gateway

mkdir -p /tmp/tyk-backups

if command -V systemctl >/dev/null 2>&1; then
    cp /lib/systemd/system/${SERVICE_NAME}.service /tmp/tyk-backups
    echo Backed up systemd service file
    fi
fi
