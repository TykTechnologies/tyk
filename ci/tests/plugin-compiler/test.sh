#!/bin/bash
function setup {
	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk:${tag}"}
	export PLUGIN_COMPILER_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-plugin-compiler:${tag}"}
}

setup

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

# if params were not sent, then attempt to get them from env vars
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
    GOOS=$(go env GOOS)
    GOARCH=$(go env GOARCH)
fi

compose='docker-compose'
# composev2 is a client plugin
[[ $(docker version --format='{{ .Client.Version }}') =~ "20.10" ]] && compose='docker compose'

export tag=$1

trap "$compose down" EXIT

PLUGIN_SOURCE_PATH=$PWD/testplugin
rm -fv $PLUGIN_SOURCE_PATH/*.so || true
docker run --rm -v $PLUGIN_SOURCE_PATH:/plugin-source $PLUGIN_COMPILER_IMAGE testplugin.so
cp $PLUGIN_SOURCE_PATH/*.so $PLUGIN_SOURCE_PATH/testplugin.so 

$compose up -d

curl -vvv http://localhost:8080/goplugin/headers
curl http://localhost:8080/goplugin/headers | jq -e '.headers.Foo == "Bar"' || { $compose logs gw; exit 1; }
