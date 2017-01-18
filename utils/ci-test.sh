#!/bin/bash

set -e

# print a command and execute it
show() {
	echo "$@"
	eval "$@"
}

fatal() {
	echo "$@"
	exit 1
}

PKGS="$(go list ./... | grep -v /vendor/)"

show go test -v $PKGS
show go test -v -tags coprocess $PKGS

show go vet -v $PKGS
show go vet -v -tags coprocess $PKGS

GOFILES=$(find * -name '*.go' -not -path 'vendor/*')

FMT_FILES="$(gofmt -s -l $GOFILES)"
if [[ -n $FMT_FILES ]]; then
	fatal "Run 'gofmt -s -w' on these files:\n$FMT_FILES"
fi

IMP_FILES="$(goimports -l $GOFILES)"
if [[ -n $IMP_FILES ]]; then
	fatal "Run 'goimports -w' on these files:\n$IMP_FILES"
fi
