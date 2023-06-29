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

# if params were not sent, then attempt to get them from env vars
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
    GOOS=$(go env GOOS)
    GOARCH=$(go env GOARCH)
fi

# pass plugin params to docker compose
set -x
export plugin_version=$(echo $1 | perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"')
export plugin_os=${GOOS}
export plugin_arch=${GOARCH}

compose='docker-compose'
# composev2 is a client plugin
[[ $(docker version --format='{{ .Client.Version }}') =~ "20.10" ]] && compose='docker compose'

export tag=$1

trap "$compose down" EXIT

rm -fv testplugin/*.so || true
docker run --rm -v `pwd`/testplugin:/plugin-source tykio/tyk-plugin-compiler:${tag} testplugin.so

$compose up -d

sleep 2 # Wait for init

curl -vvv http://localhost:8080/goplugin/headers
curl http://localhost:8080/goplugin/headers | jq -e '.headers.Foo == "Bar"' || { $compose logs gw; exit 1; }
