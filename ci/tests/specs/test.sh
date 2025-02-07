#!/bin/bash
set -eo pipefail

function setup {
	local tag=${1:-"v0.0.0"}
	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}

	docker pull -q $GATEWAY_IMAGE
}

setup $1

trap "task down" EXIT

echo "Creating .env file..."
echo "PORTMAN_API_Key=example_gateway_secret" > ".env"

task up

task tests
