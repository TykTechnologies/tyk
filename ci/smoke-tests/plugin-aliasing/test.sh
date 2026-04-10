#!/bin/bash
set -eo pipefail

function setup {
	local tag=${1:-"v0.0.0"}

	# Setup required env vars for docker compose
	export GATEWAY_IMAGE=${GATEWAY_IMAGE:-"tykio/tyk-gateway:${tag}"}
	export PLUGIN_COMPILER_IMAGE=${PLUGIN_COMPILER_IMAGE:-"tykio/tyk-plugin-compiler:${tag}"}

	docker pull -q $GATEWAY_IMAGE || true
	docker pull -q $PLUGIN_COMPILER_IMAGE || true
}

setup $1

trap "docker compose down" EXIT

GATEWAY_VERSION=$(docker run --rm -t $GATEWAY_IMAGE --version 2>&1)
GATEWAY_VERSION=$(echo $GATEWAY_VERSION | perl -n -e'/(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"')

rm -rfv foobar-plugin/*.so helloworld-plugin/*.so

docker volume create plugin-aliasing-go-mod-cache
docker volume create plugin-aliasing-go-build-cache

cache_args="-v plugin-aliasing-go-mod-cache:/go/pkg/mod -v plugin-aliasing-go-build-cache:/root/.cache/go-build"

docker run --rm -e GO_GET=1 $cache_args -v `pwd`/foobar-plugin:/plugin-source $PLUGIN_COMPILER_IMAGE foobar-plugin.so
docker run --rm -e GO_GET=1 $cache_args -v `pwd`/helloworld-plugin:/plugin-source $PLUGIN_COMPILER_IMAGE helloworld-plugin.so

# if params were not sent, then attempt to get them from env vars
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
    GOOS=$(go env GOOS)
    GOARCH=$(go env GOARCH)
fi

# pass plugin params
export plugin_version=${GATEWAY_VERSION}
export plugin_os=${GOOS}
export plugin_arch=${GOARCH}

docker compose up -d --wait --force-recreate || { docker compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-helloworld-1/headers
curl http://localhost:8080/goplugin-helloworld-1/headers | jq -e '.headers.Hello == "World"' || { docker compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-helloworld-2/headers
curl http://localhost:8080/goplugin-helloworld-2/headers | jq -e '.headers.Hello == "World"' || { docker compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-foobar-1/headers
curl http://localhost:8080/goplugin-foobar-1/headers | jq -e '.headers.Foo == "Bar"' || { docker compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-foobar-2/headers
curl http://localhost:8080/goplugin-foobar-2/headers | jq -e '.headers.Foo == "Bar"' || { docker compose logs gw; exit 1; }