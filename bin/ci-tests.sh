#!/bin/bash

export TYK_GW_STORAGE_HOST=${TYK_GW_STORAGE_HOST:-redis}
export TYK_GW_STORAGE_ADDRS=${TYK_GW_STORAGE_HOST}:6379

TEST_TIMEOUT=15m

package=$(go list .)
packages=$(go list ./... | tail -n +2 | sed -e "s|$package/||g" | egrep -v -e '(\/|testing)')

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

set -x

for pkg in ${packages}; do
    go test ${OPTS} -timeout ${TEST_TIMEOUT} -coverprofile=${pkg}.cov ./${pkg}/...
done

# run rpc tests separately (@titpetric: why? how is this not covered above?)
rpc_tests='SyncAPISpecsRPC|OrgSessionWithRPCDown'
go test -count=1 -timeout ${TEST_TIMEOUT} -v -coverprofile=gateway-rpc.cov github.com/TykTechnologies/tyk/gateway -p 1 -run '"'${rpc_tests}'"'
