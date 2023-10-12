#!/bin/bash
function setup {
	local tag=${1:-"v6.0.0"}
	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}
}

set -eo pipefail

setup $1

trap "docker compose down --remove-orphans" EXIT

set -x
docker compose up -d --wait --force-recreate

./api_test.sh || { $compose logs gw; exit 1; }
