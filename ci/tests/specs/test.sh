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

# Create mount directories with world-writable permissions so the
# nonroot gateway (uid 65532) can write API definitions and policies.
mkdir -p apps policies 2>/dev/null
chmod 777 apps policies 2>/dev/null

task up

task tests
