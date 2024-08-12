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

# set tags for the CI tests run / plugin builds

tags="goplugin dev"

# build Go-plugin used in tests
echo "Building go plugin"
go build -tags "${tags}" -buildmode=plugin       -o ./test/goplugins/goplugins.so      ./test/goplugins
go build -tags "${tags}" -buildmode=plugin -race -o ./test/goplugins/goplugins_race.so ./test/goplugins

for pkg in ${PKGS}; do
    coveragefile=`echo "$pkg" | awk -F/ '{print $NF}'`

    echo go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${coveragefile}.cov ${pkg} -tags "${tags}"
    go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${coveragefile}.cov ${pkg} -tags "${tags}"
done

# run rpc tests separately
rpc_tests='SyncAPISpecsRPC|OrgSessionWithRPCDown'
go test -count=1 -timeout ${TEST_TIMEOUT} -v -coverprofile=gateway-rpc.cov github.com/TykTechnologies/tyk/gateway -p 1 -run '"'${rpc_tests}'"'
