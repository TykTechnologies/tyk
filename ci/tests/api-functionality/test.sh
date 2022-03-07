#!/bin/bash

set -eo pipefail

function usage {
    local progname=$1
    cat <<EOF
Usage:
$progname <tag>

Runs the tyk-gateway container image with the given tag with a basic api defenition that redirects to
httpbin and tests if evrything is in order.
Requires docker compose.
EOF
    exit 1
}

compose='docker-compose'
# composev2 is a client plugin
[[ $(docker version --format='{{ .Client.Version }}') == "20.10.11" ]] && compose='docker compose'

[[ -z $1 ]] && usage $0
export tag=$1

trap "$compose down" EXIT

$compose up -d
sleep 2 # Wait for init
./api_test.sh || { $compose logs gw; exit 1; }
