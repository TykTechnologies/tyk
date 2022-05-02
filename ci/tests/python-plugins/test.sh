#!/bin/bash

set -eo pipefail

function usage {
    local progname=$1
    cat <<EOF
Usage:
$progname <tag>

Builds the python plugin in src using the supplied tag and tests it in the corresponding gw image.
Requires docker compose.
EOF
    exit 1
}

check_gw_status() {
    [[ -z $1 ]] && exit 1
    gwbase=$1
    echo "Checking Tyk GW status..."
    status=$(curl -s "${gwbase}/hello" | jq -r '.status')
    [[ "$status" != "pass" ]] && return 1
    redis_status=$(curl -s "${gwbase}/hello" | jq -r '.details.redis.status')
    [[ "$redis_status" != "pass" ]] && return 1
    return 0
}

[[ -z "$1" ]] && usage "$0"
export tag=$1

# set the env vars MAX_RETRIES and WAIT_TIME to reasonably safe values
# if docker compose takes more time  to startup in CI/CD environments.
[[ -z "$MAX_RETRIES" ]] && export MAX_RETRIES=10
[[ -z "$WAIT_TIME" ]] && export WAIT_TIME=3

compose="docker-compose"
[[ $(docker version --format='{{ .Client.Version }}') =~ 20.10 ]] &&  compose="docker compose"

$compose build && $compose up -d
trap '$compose down' EXIT

counter=0
# Check if gw is up, until the set no. of retries is exhausted.
while ! check_gw_status "http://localhost:8080"
do
    if [ $counter -ge $MAX_RETRIES ] ; then
        echo "ERROR: Gateway not yet up in $MAX_RETRIES tries.."
        exit 1
    fi
    echo "Gateway & gateway redis is not yet up, waiting a bit..."
    counter=$((counter+1))
    sleep $WAIT_TIME
done

curl http://localhost:8080/pyplugin/headers | jq -e '.headers.Foo == "Bar"'
exit 0
