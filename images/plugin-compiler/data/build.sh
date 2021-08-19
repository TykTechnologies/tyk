#!/bin/bash

set -xe

plugin_name=$1

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

# Plugin's vendor folder, has precendence over the cached vendor'd dependencies from tyk
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

go build -buildmode=plugin -o $plugin_name \
    && mv $plugin_name $PLUGIN_SOURCE_PATH
