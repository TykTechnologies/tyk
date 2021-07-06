#!/bin/bash

set -xe

plugin_name=$1
plugin_path=$(date +%s)-$plugin_name

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name>

EOF
}

if [ -z "$plugin_name" ]; then
    usage
    exit 1
fi


yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true


cd $PLUGIN_BUILD_PATH

# Handle if plugin has own vendor folder, and ignore error if not
[ -f go.mod ] && [ ! -d ./vendor ] && GO111MODULE=on go mod vendor
# Ensure that go modules not used
rm -rf go.mod

# We do not needd to care whicch version of Tyk vendored in plugin, since we going to use version inside compiler
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


go build -buildmode=plugin -ldflags "-pluginpath=$plugin_path" -o $plugin_name \
&& mv $plugin_name $PLUGIN_SOURCE_PATH
