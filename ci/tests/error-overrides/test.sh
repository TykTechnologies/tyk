#!/bin/bash
set -eo pipefail

function setup {
	local tag=${1:-"v0.0.0"}
	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}

	# Only pull if image doesn't exist locally
	if ! docker image inspect $GATEWAY_IMAGE > /dev/null 2>&1; then
		docker pull -q $GATEWAY_IMAGE
	fi
}

setup $1

trap "task teardown" EXIT

# Run tasks sequentially
task setup
task info
task test
