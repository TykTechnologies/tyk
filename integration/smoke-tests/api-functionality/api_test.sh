#!/bin/bash

/opt/tyk-gateway/tyk --conf /opt/tyk-gateway/tyk.conf >/dev/null 2>&1 &
sleep 2
curl -s -XGET -H "Accept: application/json" "http://localhost:8080/smoke-test-api/?arg=test"| jq -r '.args.arg'| grep -q -x test

