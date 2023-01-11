#!/bin/bash

set -eo pipefail

function usage {
    local progname=$1
    cat <<EOF
Usage:
$progname <tag>

Builds the python plugin in src using the supplied tag and tests it in the corresponding gw image.
Requires docker compose.
EOF
    exit 1
}

[[ -z $1 ]] && usage $0
export tag=$1

docker-compose build && docker-compose up -d
curl http://localhost:8080/pyplugin/headers | jq -e '.headers.Foo == "Bar"'
docker-compose down
