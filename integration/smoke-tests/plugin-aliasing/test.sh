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

function logAndStopDocker {
  docker-compose logs
  docker-compose down
  exit $1
}


function testAPIs {
  curl -vvv http://localhost:8080/goplugin-helloworld-1/headers
  curl http://localhost:8080/goplugin-helloworld-1/headers | jq -e '.headers.Hello == "World"'

  curl -vvv http://localhost:8080/goplugin-helloworld-2/headers
  curl http://localhost:8080/goplugin-helloworld-2/headers | jq -e '.headers.Hello == "World"'

  curl -vvv http://localhost:8080/goplugin-foobar-1/headers
  curl http://localhost:8080/goplugin-foobar-1/headers | jq -e '.headers.Foo == "Bar"'

  curl -vvv http://localhost:8080/goplugin-foobar-2/headers
  curl http://localhost:8080/goplugin-foobar-2/headers | jq -e '.headers.Foo == "Bar"'
}

[[ -z $1 ]] && usage $0
export tag=$1

rm -fv foobar-plugin/*.so || true
docker run --rm -v `pwd`/foobar-plugin:/plugin-source tykio/tyk-plugin-compiler:${tag} foobar-plugin.so

rm -fv helloworld-plugin/*.so || true
docker run --rm -v `pwd`/helloworld-plugin:/plugin-source tykio/tyk-plugin-compiler:${tag} helloworld-plugin.so

docker-compose up -d
sleep 2 # Wait for init

if testAPIs; then
  logAndStopDocker 0
else
  logAndStopDocker 1
fi