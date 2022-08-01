#!/bin/bash

TEST_TIMEOUT=15m

PKGS="$(go list ./...)"

# Support passing custom flags (-json, etc.)
OPTS="$@"
if [[ -z "$OPTS" ]]; then
	OPTS="-race -count=1 -failfast -v"
fi

export PKG_PATH=${GOPATH}/src/github.com/TykTechnologies/tyk

# exit on non-zero exit from go test/vet
set -e

# build Go-plugin used in tests
echo "Building go plugin"
go build -o ./test/goplugins/goplugins.so -buildmode=plugin ./test/goplugins

for pkg in ${PKGS}; do
    tags=""
    if [[ ${pkg} == *"goplugin" ]]; then
        tags="-tags 'goplugin'"
    fi

    coveragefile=`echo "$pkg" | awk -F/ '{print $NF}'`

    echo go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${coveragefile}.cov ${pkg} ${tags}
    go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${coveragefile}.cov ${pkg} ${tags}
done

# run rpc tests separately
rpc_tests='SyncAPISpecsRPC|OrgSessionWithRPCDown'
go test -count=1 -timeout ${TEST_TIMEOUT} -v -coverprofile=gateway-rpc.cov github.com/TykTechnologies/tyk/gateway -p 1 -run '"'${rpc_tests}'"'
