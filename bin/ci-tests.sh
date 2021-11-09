#!/bin/bash

TEST_TIMEOUT=15m

# print a command and execute it
show() {
	echo "$@" >&2
	eval "$@"
}

fatal() {
	echo "$@" >&2
	exit 1
}

PKGS="$(go list ./...)"

export PKG_PATH=${GOPATH}/src/github.com/TykTechnologies/tyk

# build Go-plugin used in tests
go build -o ./test/goplugins/goplugins.so -buildmode=plugin ./test/goplugins || fatal "building Go-plugin failed"

for pkg in ${PKGS}; do
    tags=""

    # TODO: Remove skipRace variable after solving race conditions in tests.
    skipRace=false
    if [[ ${pkg} == *"grpc" ]]; then
        skipRace=true
    elif [[ ${pkg} == *"goplugin" ]]; then
        skipRace=true
        tags="-tags 'goplugin'"
    fi

    race="-race"

    if [[ ${skipRace} = true ]]; then
        race=""
    fi
    coveragefile=`echo "$pkg" | awk -F/ '{print $NF}'`
    show go test ${race} -timeout ${TEST_TIMEOUT} -v -coverprofile=${coveragefile}.cov ${pkg} ${tags} || fatal "Test Failed"
    show go vet ${tags} ${pkg} || fatal "go vet errored"
done

# run rpc tests separately
rpc_tests='SyncAPISpecsRPC|OrgSessionWithRPCDown'
show go test -timeout ${TEST_TIMEOUT} -v -coverprofile=gateway-rpc.cov github.com/TykTechnologies/tyk/gateway -p 1 -run '"'${rpc_tests}'"' || fatal "Test Failed"
