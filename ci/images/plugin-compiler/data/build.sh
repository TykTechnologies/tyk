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

set -x
mkdir -p $PLUGIN_BUILD_PATH
# Plugin's vendor folder, has precedence over the cached vendor'd dependencies from tyk
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true

cd $PLUGIN_BUILD_PATH

# Handle if plugin has own vendor folder, and ignore error if not
[ -f go.mod ] && [ ! -d ./vendor ] && GO111MODULE=on go mod vendor || true

# We do not need to care which version of Tyk vendored in plugin, since we going to use version inside compiler
rm -rf $PLUGIN_BUILD_PATH/vendor/github.com/TykTechnologies/tyk

# Copy plugin vendored pkgs to GOPATH
if [ -d ./vendor ]; then
	cp -rf $PLUGIN_BUILD_PATH/vendor/* $GOPATH/src
        rm -rf $PLUGIN_BUILD_PATH/vendor
fi

# Ensure that GW package versions have priorities

# We can't just copy Tyk dependencies on top of plugin dependencies, since different package versions have different file structures
# First we need to find which deps GW already has, remove this folders, and after copy fresh versions from GW

# github.com and rest of packages have different nesting levels, so have to handle it separately
ls -d $TYK_GW_PATH/vendor/github.com/*/* | sed "s|$TYK_GW_PATH/vendor|$GOPATH/src|g" | xargs --no-run-if-empty -d '\n' rm -rf
ls -d $TYK_GW_PATH/vendor/*/* | sed "s|$TYK_GW_PATH/vendor|$GOPATH/src|g" | grep -v github | xargs --no-run-if-empty -d '\n' rm -rf

# Copy GW dependencies
if [ -d $TYK_GW_PATH/vendor ]; then
	cp -rf $TYK_GW_PATH/vendor/* $GOPATH/src
	rm -rf $TYK_GW_PATH/vendor
fi

rm /go/src/modules.txt

set +x

# Dump settings for inspection

echo "PLUGIN_BUILD_PATH: ${PLUGIN_BUILD_PATH}"
echo "PLUGIN_SOURCE_PATH: ${PLUGIN_SOURCE_PATH}"
echo "CC: ${CC}"
echo "plugin_name: ${plugin_name}"

set -x

CGO_ENABLED=1 GO111MODULE=off CC=$CC GOOS=$GOOS GOARCH=$GOARCH go build -buildmode=plugin -o $plugin_name
mv $plugin_name $PLUGIN_SOURCE_PATH
