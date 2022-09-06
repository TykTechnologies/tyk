#!/bin/bash
set -xe

CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' $TYK_GW_PATH/gateway/version.go)
plugin_name=$1
plugin_id=$2
# GOOS and GOARCH can be send to override the name of the plugin
GOOS=$3
GOARCH=$4

PLUGIN_BUILD_PATH="/go/src/plugin_${plugin_name%.*}$plugin_id"

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name> <plugin_id> [<GOOS>] [<GOARCH>]

<plugin_id> is optional
EOF
}

# if params were not send, then attempt to get them from env vars
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
  GOOS=$(go env GOOS)
  GOARCH=$(go env GOARCH)
fi

if [ -z "$plugin_name" ]; then
    usage
    exit 1
fi

# if arch and os present then update the name of file with those params
if [[ $GOOS != "" ]] && [[ $GOARCH != "" ]]; then
  plugin_name="${plugin_name%.*}_${CURRENTVERS}_${GOOS}_${GOARCH}.so"
fi


mkdir -p $PLUGIN_BUILD_PATH
# Plugin's vendor folder, has precedence over the cached vendor'd dependencies from tyk
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true

cd $PLUGIN_BUILD_PATH

# Handle if plugin has own vendor folder, and ignore error if not
[ -f go.mod ] && [ ! -d ./vendor ] && GO111MODULE=on go mod vendor
# Ensure that go modules not used
rm -rf go.mod

# We do not need to care which version of Tyk vendored in plugin, since we going to use version inside compiler
rm -rf $PLUGIN_BUILD_PATH/vendor/github.com/TykTechnologies/tyk

# Copy plugin vendored pkgs to GOPATH
yes | cp -rf $PLUGIN_BUILD_PATH/vendor/* $GOPATH/src || true \
        && rm -rf $PLUGIN_BUILD_PATH/vendor

# Ensure that GW package versions have priorities

# We can't just copy Tyk dependencies on top of plugin dependencies, since different package versions have different file structures
# First we need to find which deps GW already has, remove this folders, and after copy fresh versions from GW

# github.com and rest of packages have different nesting levels, so have to handle it separately
ls -d $TYK_GW_PATH/vendor/github.com/*/* | sed "s|$TYK_GW_PATH/vendor|$GOPATH/src|g" | xargs -d '\n' rm -rf
ls -d $TYK_GW_PATH/vendor/*/* | sed "s|$TYK_GW_PATH/vendor|$GOPATH/src|g" | grep -v github | xargs -d '\n' rm -rf

# Copy GW dependencies
yes | cp -rf $TYK_GW_PATH/vendor/* $GOPATH/src
rm -rf $TYK_GW_PATH/vendor

rm /go/src/modules.txt

if [[ $GOOS == "arm64" ]]; then
    CC=aarch64-linux-gnu-gcc
else
    CC=$(go env CC)
fi

GO111MODULE=off GOOS=$GOOS GOARCH=$GOARCH CC=$CC  go build -buildmode=plugin -o $plugin_name \
    && mv $plugin_name $PLUGIN_SOURCE_PATH
