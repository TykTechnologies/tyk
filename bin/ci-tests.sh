#!/bin/bash

export TYK_GW_STORAGE_HOST=${TYK_GW_STORAGE_HOST:-redis}
export TYK_GW_STORAGE_ADDRS=${TYK_GW_STORAGE_HOST}:6379

TEST_TIMEOUT=15m

PKGS="$(go list ./...)"

# Support passing custom flags (-json, etc.)
OPTS="$@"
if [[ -z "$OPTS" ]]; then
	OPTS="-race -count=1 -tags goplugin -v"
fi

export PKG_PATH=${GOPATH}/src/github.com/TykTechnologies/tyk

# exit on non-zero exit from go test/vet
set -e

# build Go-plugin used in tests
echo "Building go plugin"
go build -race -o ./test/goplugins/goplugins.so -buildmode=plugin ./test/goplugins

for pkg in ${PKGS}; do
    coveragefile=`echo "$pkg" | awk -F/ '{print $NF}'`

    echo go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${coveragefile}.cov ${pkg}
    go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${coveragefile}.cov ${pkg}
done

# run rpc tests separately
rpc_tests='SyncAPISpecsRPC|OrgSessionWithRPCDown'
go test -count=1 -timeout ${TEST_TIMEOUT} -v -coverprofile=gateway-rpc.cov github.com/TykTechnologies/tyk/gateway -p 1 -run '"'${rpc_tests}'"'
