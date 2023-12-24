#!/bin/bash
set -e

echo "Running benchmarks"


go test -count=5 -run='^$' -bench BenchmarkPurgeLapsedOAuthTokens github.com/TykTechnologies/tyk/gateway