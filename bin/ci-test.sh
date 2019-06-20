#!/bin/bash

TEST_TIMEOUT=2m

# print a command and execute it
show() {
	echo "$@" >&2
	eval "$@"
}

fatal() {
	echo "$@" >&2
	exit 1
}

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
fi

PKGS="$(go list -tags "coprocess python grpc" ./...)"

go get -t

# build Go-plugin used in tests
go build -race -o ./test/goplugins/goplugins.so -buildmode=plugin ./test/goplugins || fatal "building Go-plugin failed"

for pkg in $PKGS; do
    TAGS=""
    if [[ ${pkg} == *"coprocess/grpc" ]]; then
        TAGS="-tags 'coprocess grpc'"
    elif [[ ${pkg} == *"coprocess/python" ]]; then
        TAGS="-tags 'coprocess python'"
    elif [[ ${pkg} == *"coprocess" ]]; then
        TAGS="-tags 'coprocess'"
    fi

    race=""

    if [[ -z ${TAGS} ]]; then
        race="-race"
    fi

    show go test -v ${race} -timeout ${TEST_TIMEOUT} -coverprofile=test.cov $pkg ${TAGS} || fatal "Test Failed"
done

show go vet $PKGS || fatal "go vet errored"
