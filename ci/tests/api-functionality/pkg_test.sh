#!/bin/bash
set -exo pipefail

/opt/tyk-gateway/tyk --conf /opt/tyk-gateway/tyk.conf >/dev/null 2>&1 &
sleep 2
./api_test.sh
