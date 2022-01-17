#!/bin/sh

# Generated by: tyk-ci/wf-gen
# Generated on: Mon Jan 17 17:57:49 UTC 2022

# Generation commands:
# ./pr.zsh -p -base TD-835/Sync-releng-m4-templates -branch TD-835/Sync-releng-m4-templates -title Sync m4 release engineering templates -repos tyk
# m4 -E -DxREPO=tyk


if command -V systemctl >/dev/null 2>&1; then
    if [ ! -f /lib/systemd/system/tyk-gateway.service ]; then
        cp /opt/tyk-gateway/install/inits/systemd/system/tyk-gateway.service /lib/systemd/system/tyk-gateway.service
    fi
else
    if [ ! -f /etc/init.d/tyk-gateway ]; then
        cp /opt/tyk-gateway/install/inits/sysv/init.d/tyk-gateway /etc/init.d/tyk-gateway
    fi
fi
