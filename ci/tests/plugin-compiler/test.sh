#!/bin/bash
set -eo pipefail

function setup {
	local tag=${1:-"v0.0.0"}

	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}
	export PLUGIN_COMPILER_IMAGE=${PLUGIN_COMPILER_IMAGE:-"tykio/tyk-plugin-compiler:${tag}"}

	docker pull -q $GATEWAY_IMAGE
	docker pull -q $PLUGIN_COMPILER_IMAGE
}

setup $1

trap "docker compose down --remove-orphans" EXIT

# Clean up loose .so files, rebuild plugin and normalize plugin name.
PLUGIN_SOURCE_PATH=$PWD/testdata/test-plugin
rm -fv $PLUGIN_SOURCE_PATH/*.so || true
docker run --rm -v $PLUGIN_SOURCE_PATH:/plugin-source $PLUGIN_COMPILER_IMAGE plugin.so
cp $PLUGIN_SOURCE_PATH/*.so $PLUGIN_SOURCE_PATH/plugin.so 

# Cross compile to arm64
docker run --rm -e GOARCH=arm64 -v $PLUGIN_SOURCE_PATH:/plugin-source $PLUGIN_COMPILER_IMAGE plugin.so

docker compose up -d --wait --force-recreate || { docker compose logs gw; exit 1; }

curl http://localhost:8080/goplugin/headers | jq -e '.headers.Foo == "Bar"' || { docker compose logs gw; exit 1; }
