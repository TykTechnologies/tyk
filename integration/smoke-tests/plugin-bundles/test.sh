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
rm -fv testplugin/*.so || true
docker run --rm -v `pwd`/testplugin:/plugin-source tykio/tyk-plugin-compiler:${tag} testplugin.so

# bundle the plugin
cd testplugin
docker run --rm -w "/tmp" -v $(pwd):/tmp --entrypoint "/bin/sh" -it tykio/tyk-gateway:${tag} -c '/opt/tyk-gateway/tyk bundle build -y'
cd ..

docker-compose up -d
sleep 2 # Wait for init

curl -vvv http://localhost:8080/goplugin-1/headers -H "Authorization:abc"

# check post request middleware
curl http://localhost:8080/goplugin-1/headers -H "Authorization:abc" | jq -e '.headers.Hello == "World"' || { $compose logs gw; exit 1; }

# check pre request middleware
$compose logs gw | grep 'request received with url /goplugin-1/headers' || { $compose logs gw; exit 1; }

# check auth middleware
curl -s -i http://localhost:8080/goplugin-1/headers | head -1 | grep '403 Forbidden' || { $compose logs gw; exit 1; }

# check response middleware
curl --head http://localhost:8080/goplugin-1/headers -H "Authorization:abc" | grep 'Foo: Bar' || { $compose logs gw; exit 1; }



curl -vvv http://localhost:8080/goplugin-2/headers -H "Authorization:abc"

# check post request middleware
curl http://localhost:8080/goplugin-2/headers -H "Authorization:abc" | jq -e '.headers.Hello == "World"' || { $compose logs gw; exit 1; }

# check pre request middleware
$compose logs gw | grep 'request received with url /goplugin-2/headers' || { $compose logs gw; exit 1; }

# check auth middleware
curl -s -i  http://localhost:8080/goplugin-2/headers | head -1 | grep '403 Forbidden' || { $compose logs gw; exit 1; }

# check response middleware
curl --head http://localhost:8080/goplugin-2/headers -H "Authorization:abc" | grep 'Foo: Bar' || { $compose logs gw; exit 1; }