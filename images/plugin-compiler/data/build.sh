#!/bin/bash

set -xe

CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' $TYK_GW_PATH/gateway/version.go)
plugin_name=$1

plugin_id=$2
# GOOS and GOARCH can be send to override the name of the plugin
GOOS=$3
GOARCH=$4
CGOENABLED=0

PLUGIN_BUILD_PATH="/go/src/plugin_${plugin_name%.*}$plugin_id"


function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name>

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

if [[ $GOOS != "linux" ]];then
    CGOENABLED=1
fi

mkdir -p $PLUGIN_BUILD_PATH
# Plugin's vendor folder, has precedence over the cached vendor'd dependencies from tyk
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true

cd $PLUGIN_BUILD_PATH
# if plugin has go.mod
[ -f go.mod ] && [ ! -d vendor ] && go mod vendor
rm go.mod

# Ensure that GW package versions have priorities

# We can't just copy Tyk dependencies on top of plugin dependencies, since different package versions have different file structures
# First we need to find which deps GW already has, remove this folders, and after copy fresh versions from GW
# ls -d /tmp/vendor/*

# github.com and rest of packages have different nesting levels, so have to handle it separately
# ls -d /tmp/vendor/github.com/*/* | sed "s|/tmp/vendor|$PLUGIN_BUILD_PATH/vendor|g" | xargs -d '\n' rm -rf
# ls -d /tmp/vendor/*/* | sed "s|/tmp/vendor|$PLUGIN_BUILD_PATH/vendor|g" | grep -v github | xargs -d '\n' rm -rf

# Copy GW dependencies
# yes | cp -rf /tmp/vendor/* $PLUGIN_BUILD_PATH/vendor

GO111MODULE=off CGO_ENABLE=$CGO_ENABLE GOOS=$GOOS GOARCH=$GOARCH  go build -buildmode=plugin -o $plugin_name \
    && mv $plugin_name $PLUGIN_SOURCE_PATH
