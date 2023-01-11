#!/bin/bash

set -exo pipefail

#Just print the response for verbosity before testing the output
curl -s -XGET -H "Accept: application/json" "http://localhost:8080/smoke-test-api/?arg=test"
curl -s -XGET -H "Accept: application/json" "http://localhost:8080/smoke-test-api/?arg=test"| jq -e '.args.arg == "test"'

