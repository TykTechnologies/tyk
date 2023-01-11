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

compose='docker-compose'
# composev2 is a client plugin
[[ $(docker version --format='{{ .Client.Version }}') == "20.10.11" ]] && compose='docker compose'

[[ -z $1 ]] && usage $0
export tag=$1

trap "$compose down" EXIT

rm -fv foobar-plugin/*.so || true
docker run --rm -v `pwd`/foobar-plugin:/plugin-source tykio/tyk-plugin-compiler:${tag} foobar-plugin.so

rm -fv helloworld-plugin/*.so || true
docker run --rm -v `pwd`/helloworld-plugin:/plugin-source tykio/tyk-plugin-compiler:${tag} helloworld-plugin.so

docker-compose up -d
sleep 2 # Wait for init

curl -vvv http://localhost:8080/goplugin-helloworld-1/headers
curl http://localhost:8080/goplugin-helloworld-1/headers | jq -e '.headers.Hello == "World"' || { $compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-helloworld-2/headers
curl http://localhost:8080/goplugin-helloworld-2/headers | jq -e '.headers.Hello == "World"' || { $compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-foobar-1/headers
curl http://localhost:8080/goplugin-foobar-1/headers | jq -e '.headers.Foo == "Bar"' || { $compose logs gw; exit 1; }

curl -vvv http://localhost:8080/goplugin-foobar-2/headers
curl http://localhost:8080/goplugin-foobar-2/headers | jq -e '.headers.Foo == "Bar"' || { $compose logs gw; exit 1; }