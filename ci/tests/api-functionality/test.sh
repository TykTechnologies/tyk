#!/bin/bash
function setup {
	local tag=${1:-"v6.0.0"}
	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}
}

set -eo pipefail

setup $1

compose='docker-compose'
# composev2 is a client plugin
[[ $(docker version --format='{{ .Client.Version }}') == "20.10.11" ]] && compose='docker compose'

trap "$compose down" EXIT

$compose up -d
./api_test.sh || { $compose logs gw; exit 1; }
