#!/bin/bash

set -exo pipefail

#Just print the response for verbosity before testing the output
# retry count raised from 5 to 10 (same 10s delay): the gateway's
# redis-backed rate limiter/proxy layer can keep returning 503 for
# ~50-60s after startup on slower images, which used to exhaust the
# original 5 retries (~50s budget) before the gateway was ready.
curl -s --retry 10 --retry-delay 10 --retry-all-errors -H "Accept: application/json" "http://localhost:8080/smoke-test-api/?arg=test"
curl -s --retry 10 --retry-delay 10 --retry-all-errors -H "Accept: application/json" "http://localhost:8080/smoke-test-api/?arg=test"| jq -e '.args.arg == "test"'

