#!/bin/bash

TEST_TIMEOUT=5m

# print a command and execute it
show() {
	echo "$@" >&2
	eval "$@"
}

fatal() {
	echo "$@" >&2
	exit 1
}

race=""
if [[ ${LATEST_GO} ]]; then
    FMT_FILES=$(gofmt -l . | grep -v vendor)
    if [[ -n $FMT_FILES ]]; then
        fatal "Run 'gofmt -w' on these files:\n$FMT_FILES"
    fi

    echo "gofmt check is ok!"

    IMP_FILES="$(goimports -l . | grep -v vendor)"
    if [[ -n $IMP_FILES ]]; then
        fatal "Run 'goimports -w' on these files:\n$IMP_FILES"
    fi

    echo "goimports check is ok!"

    # Run with race if latest
    race="-race"
fi

PKGS="$(go list ./...)"

go get -t

export PKG_PATH=$GOPATH/src/github.com/TykTechnologies/tyk

# build Go-plugin used in tests
go build ${race} -o ./test/goplugins/goplugins.so -buildmode=plugin ./test/goplugins || fatal "building Go-plugin failed"

for pkg in $PKGS; do
    tags=""

    # TODO: Remove skipRace variable after solving race conditions in tests.
    skipRace=false
    if [[ ${pkg} == *"grpc" ]]; then
        skipRace=true
    elif [[ ${pkg} == *"goplugin" ]]; then
        tags="-tags 'goplugin'"
    fi

    race=""

    # Some tests should not be run with -race. Therefore, test them with penultimate Go version.
    # And, test with -race in latest Go version.
    if [[ ${LATEST_GO} && ${skipRace} = false ]]; then
        race="-race"
    fi

    show go test -v ${race} -timeout ${TEST_TIMEOUT} -coverprofile=test.cov $pkg ${tags} || fatal "Test Failed"
    show go vet ${tags} $pkg || fatal "go vet errored"
done
