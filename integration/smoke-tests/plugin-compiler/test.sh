#!/bin/bash

set -eo pipefail

function usage {
    local progname=$1
    cat <<EOF
Usage:
$progname <tag>

Builds the plugin in testplugin using the supplied tag and tests it in the corresponding gw image.
Requires docker compose.
EOF
    exit 1
}

[[ -z $1 ]] && usage $0
export tag=$1

rm -fv testplugin/*.so || true
docker run --rm -v `pwd`/testplugin:/plugin-source tykio/tyk-plugin-compiler:${tag} testplugin.so
docker-compose up -d
sleep 2 # Wait for init
curl -vvv http://localhost:8080/goplugin/headers
curl http://localhost:8080/goplugin/headers | jq -e '.headers.Foo == "Bar"'
docker-compose logs
docker-compose down 
