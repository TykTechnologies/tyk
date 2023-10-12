#!/bin/bash
function setup {
	local tag=${1:-"v6.0.0"}
	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}
	export PLUGIN_COMPILER_IMAGE=${PLUGIN_COMPILER_IMAGE:-"tykio/tyk-plugin-compiler:${tag}"}
}

set -eo pipefail

setup $1

# if params were not sent, then attempt to get them from env vars
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
    GOOS=$(go env GOOS)
    GOARCH=$(go env GOARCH)
fi

compose='docker-compose'
# composev2 is a client plugin
[[ $(docker version --format='{{ .Client.Version }}') =~ "20.10" ]] && compose='docker compose'

trap "$compose down" EXIT

PLUGIN_SOURCE_PATH=$PWD/testplugin
rm -fv $PLUGIN_SOURCE_PATH/*.so || true

set -x
echo "Hi"

docker run --rm -v $PLUGIN_SOURCE_PATH:/plugin-source $PLUGIN_COMPILER_IMAGE testplugin.so
cp $PLUGIN_SOURCE_PATH/*.so $PLUGIN_SOURCE_PATH/testplugin.so 

$compose up -d

curl -vvv http://localhost:8080/goplugin/headers
curl http://localhost:8080/goplugin/headers | jq -e '.headers.Foo == "Bar"' || { $compose logs gw; exit 1; }
