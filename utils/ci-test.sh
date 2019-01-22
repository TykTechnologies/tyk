#!/bin/bash

set -e

MATRIX=(
	"-tags 'coprocess python'"
	"-tags 'coprocess grpc'"
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

i=0

go get -t

# need to do per-pkg because go test doesn't support a single coverage
# profile for multiple pkgs
for pkg in $PKGS; do
	for opts in "${MATRIX[@]}"; do
		show go test -timeout 40s -v -coverprofile=test-$i.cov $opts $pkg \
			|| fatal "go test errored"
		let i++ || true
	done
done

if [[ ! $LATEST_GO ]]; then
	echo "Skipping race, checks, and coverage report"
	exit 0
fi

go test -race $PKGS || fatal "go test -race failed"

for opts in "${MATRIX[@]}"; do
	show go vet $opts $PKGS || fatal "go vet errored"
done

# Includes all top-level files and dirs that don't start with a dot
# (hidden). Also excludes all of vendor/.
GOFILES=$(find * -name '*.go' -not -path 'vendor/*')

FMT_FILES="$(gofmt -s -l $GOFILES)"
if [[ -n $FMT_FILES ]]; then
	fatal "Run 'gofmt -s -w' on these files:\n$FMT_FILES"
fi

IMP_FILES="$(goimports -local github.com/TykTechnologies -l $GOFILES)"
if [[ -n $IMP_FILES ]]; then
	fatal "Run 'goimports -local github.com/TykTechnologies -w' on these files:\n$IMP_FILES"
fi
