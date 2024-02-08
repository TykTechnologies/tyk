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

curl -s http://localhost:8080/pyplugin/headers | jq -e '.headers.Foo == "Bar"'
