#!/bin/bash

# SKIP_LINT=true - only run the tests

set -e

MATRIX=(
	""
	"-tags 'coprocess'"
)

# print a command and execute it
show() {
	echo "$@" >&2
	eval "$@"
}

fatal() {
	echo "$@" >&2
	exit 1
}

PKGS="$(go list ./... | grep -v /vendor/)"

for opts in "${MATRIX[@]}"; do
	show go test -v $opts $PKGS
done

if [[ $SKIP_LINT ]]; then
	echo "Skipping linting"
	exit 0
fi

for opts in "${MATRIX[@]}"; do
	show go vet -v $opts $PKGS
done

# Includes all top-level files and dirs that don't start with a dot
# (hidden). Also excludes all of vendor/.
GOFILES=$(find * -name '*.go' -not -path 'vendor/*')

FMT_FILES="$(gofmt -s -l $GOFILES)"
if [[ -n $FMT_FILES ]]; then
	fatal "Run 'gofmt -s -w' on these files:\n$FMT_FILES"
fi

IMP_FILES="$(goimports -l $GOFILES)"
if [[ -n $IMP_FILES ]]; then
	fatal "Run 'goimports -w' on these files:\n$IMP_FILES"
fi
