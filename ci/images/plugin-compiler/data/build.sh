#!/bin/bash
set -e

GATEWAY_VERSION=$(echo $GITHUB_TAG | perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"')

# Plugin compiler arguments:
#
# - 1. plugin_name = vendor-plugin.so
# - 2. plugin_id = optional, sets build folder to `/opt/plugin_{plugin_name}{plugin_id}`
# - 3. GOOS = optional override of GOOS
# - 4. GOARCH = optional override of GOARCH
#
# The script will build a plugin named according to the following:
#
# - `{plugin_name%.*}_{GATEWAY_VERSION}_{GOOS}_{GOARCH}.so`
#
# If GOOS and GOARCH are not set, it will build `{plugin_name}`.
#
# Example command: ./build.sh 
# Example output: tyk-extras_5.0.0_linux_amd64.so

plugin_name=$1
plugin_id=$2
GOOS=${3:-$(go env GOOS)}
GOARCH=${4:-$(go env GOARCH)}

# Some defaults that can be overriden with env
WORKSPACE_ROOT=$(dirname $TYK_GW_PATH)

PLUGIN_SOURCE_PATH=${PLUGIN_SOURCE_PATH:-"/plugin-source"}
PLUGIN_BUILD_PATH=${PLUGIN_BUILD_PATH:-"${WORKSPACE_ROOT}/plugin_${plugin_name%.*}$plugin_id"}

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name> <plugin_id>

<plugin_id> is optional
EOF
}

if [ -z "$plugin_name" ]; then
    usage
    exit 1
fi

# Set up arm64 cross build
CC=$(go env CC)
if [[ $GOARCH == "arm64" ]] && [[ $GOOS == "linux" ]] ; then
	CC=aarch64-linux-gnu-gcc
fi

# if arch and os present then update the name of file with those params
if [[ $GOOS != "" ]] && [[ $GOARCH != "" ]]; then
  plugin_name="${plugin_name%.*}_${GATEWAY_VERSION}_${GOOS}_${GOARCH}.so"
fi

# Copy plugin source into plugin build folder.
mkdir -p $PLUGIN_BUILD_PATH
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true

# Create worspace
cd $WORKSPACE_ROOT
go work init ./tyk
go work use ./$(basename $PLUGIN_BUILD_PATH)

# Go to plugin build path
cd $PLUGIN_BUILD_PATH

# Dump settings for inspection

echo "PLUGIN_BUILD_PATH: ${PLUGIN_BUILD_PATH}"
echo "PLUGIN_SOURCE_PATH: ${PLUGIN_SOURCE_PATH}"

set -x
CC=$CC CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build -buildmode=plugin -trimpath -o $plugin_name
set +x

mv $plugin_name $PLUGIN_SOURCE_PATH

# Clean up workspace
rm -f $WORKSPACE_ROOT/go.work
