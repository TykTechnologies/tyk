#!/bin/bash
set -e

echo "Running benchmarks"


go test -count=10 -run='^$' -bench=BenchmarkPurgeLapsedOAuthTokens . github.com/TykTechnologies/tyk/gateway