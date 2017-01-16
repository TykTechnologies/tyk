#!/bin/bash

set -e

# print a command and execute it
show() {
    echo "$@"
    eval "$@"
}

PKGS="$(go list ./... | grep -v /vendor/)"

show go test -v $PKGS
show go test -v -tags coprocess $PKGS

GOFILES=$(find * -name '*.go' -not -path 'vendor/*')

FMT_FILES="$(gofmt -s -l $GOFILES)"
if [[ -n $FMT_FILES ]]; then
	echo "Run 'gofmt -s -w' on these files:\n$FMT_FILES"
	exit 1
fi
