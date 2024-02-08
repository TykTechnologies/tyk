#!/bin/bash
set -e

echo "Running benchmarks"


go test -json -benchtime 30s -run='^$' -bench BenchmarkPurgeLapsedOAuthTokens github.com/TykTechnologies/tyk/gateway
