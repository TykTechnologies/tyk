#!/bin/bash
set -eo pipefail

function setup {
	local tag=${1:-"v0.0.0"}

	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}

	docker pull -q $GATEWAY_IMAGE
}

setup $1

trap "docker compose down --remove-orphans" EXIT

docker compose up -d --wait --force-recreate || { docker compose logs; exit 1; }

# gw has no healthcheck of its own, so `--wait` returns as soon as the
# container starts, not once Tyk has finished loading the API - retry
# to ride out that gap instead of racing the first request.
curl -s --retry 10 --retry-delay 10 --retry-all-errors http://localhost:8080/pyplugin/headers | jq -e '.headers.Foo == "Bar"'
