#!/usr/bin/env zsh

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

TRAPINT() {
    print Tearing down test env
    docker-compose -f test.yml down
}

[[ -z $1 ]] && usage $0
export tag=$1

rm -v testplugin/*.so
docker run --rm -v `pwd`/testplugin:/plugin-source tykio/tyk-plugin-compiler:${tag} testplugin.so
(cd testplugin && cp testplugin.so testplugin-${tag}.so)
docker-compose -f test.yml up
