#!/bin/bash


MATRIX=(
	"-tags 'coprocess python goplugin'"
	"-tags 'coprocess grpc goplugin'"
)
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

if [[ $LATEST_GO ]]; then
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

PKGS="$(go list ./... | grep -v /vendor/ |grep -v /tyk$)"

i=0

go get -t

# build Go-plugin used in tests
go build -race -o ./test/goplugins/goplugins.so -buildmode=plugin ./test/goplugins || fatal "building Go-plugin failed"

# need to do per-pkg because go test doesn't support a single coverage
# profile for multiple pkgs
for pkg in $PKGS; do
	for opts in "${MATRIX[@]}"; do
		show go test -race -v -timeout $TEST_TIMEOUT -coverprofile=test-$i.cov $opts $pkg \
			|| fatal "go test errored"
		let i++ || true
	done
done

for opts in "${MATRIX[@]}"; do
	show go vet $opts $PKGS || fatal "go vet errored"
done
