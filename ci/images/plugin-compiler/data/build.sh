#!/bin/bash
set -xe

CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' $TYK_GW_PATH/gateway/version.go)
plugin_name=$1
plugin_id=$2

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name> [<plugin_id>]

<plugin_id> is  optional
If you want to build for a separate platform, please provide GOARCH and GOOS as docker env vars.
EOF
}

if [ -z "$plugin_name" ]; then
    usage
    exit 1
fi

# if GOOS and GOARCH is not set from docker env, derive it from the host
# golang-X image.
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
  GOOS=$(go env GOOS)
  GOARCH=$(go env GOARCH)
fi


# if arch and os present then update the name of file with those params
if [[ $GOOS != "" ]] && [[ $GOARCH != "" ]]; then
  plugin_name="${plugin_name%.*}_${CURRENTVERS}_${GOOS}_${GOARCH}.so"
fi

echo "Building plugin: $plugin_name"

cd $TYK_GW_PATH
# get all gateway dependencies(path and versions)
go list -mod=readonly -m -f '{{ if not .Main }}{{ .Path }} {{ .Version }}{{ end }}' all > dependencies.txt

cd $PLUGIN_SOURCE_PATH
go mod download

# Get all plugin dependencies(just the paths)
go list -mod=mod -m -f '{{ if not .Main }}{{ .Path }}{{ end }}' all > dependencies.txt


# For any shared dependencies, use the version used in gateway, also download and
# update the cache and go.sum for the replaced pkg.
while IFS="" read -r dep
do
  if FULL_DEP=$(grep -E "^$dep[[:blank:]]+" $TYK_GW_PATH/dependencies.txt); then
    VER=${FULL_DEP#* }
    go mod edit -replace $dep="$dep"@"$VER"
    go mod download "$dep"@"$VER"
  fi
done < $PLUGIN_SOURCE_PATH/dependencies.txt

go mod edit -replace github.com/TykTechnologies/tyk=$TYK_GW_PATH

# Do a final verification - this updates all the go.sum entries to current.
go mod verify

rm $PLUGIN_SOURCE_PATH/dependencies.txt
rm $TYK_GW_PATH/dependencies.txt

CC=$(go env CC)
# set appropriate X-build gcc binary for arm64.
if [[ $GOARCH == "arm64" ]] && [[ $GOOS == "linux" ]] ; then
    CC=aarch64-linux-gnu-gcc
fi

CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH CC=$CC go build -buildmode=plugin -o $plugin_name
