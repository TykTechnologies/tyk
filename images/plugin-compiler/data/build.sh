#!/bin/bash

plugin_name=$1
plugin_id=$2

PLUGIN_SOURCE_PATH=${PLUGIN_SOURCE_PATH:-/plugin-source}
PLUGIN_BUILD_PATH="/go/src/${plugin_name%.*}$plugin_id"

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

mkdir -p $PLUGIN_BUILD_PATH
# Plugin's vendor folder, has precendence over the cached vendor'd dependencies from tyk
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true

cd $PLUGIN_BUILD_PATH

if [ ! -f go.mod ]; then
    echo 'Please use gomodules.'
    exit 1
fi

# replace gw with local version
#echo "replace github.com/TykTechnologies/tyk => /__w/tyk/tyk" >> go.mod

# Ensure that GW package versions have priorities

# We can't just copy Tyk dependencies on top of plugin dependencies, since different package versions have different file structures
# First we need to find which deps GW already has, remove this folders, and after copy fresh versions from GW
# ls -d /tmp/vendor/*
## Handle if plugin has own vendor folder, and ignore error if not
#
#[ -d ./vendor ] && echo 'Found vendor directory, ignoring'

# Copy GW dependencies
# yes | cp -rf /tmp/vendor/* $PLUGIN_BUILD_PATH/vendor

go build -trimpath -buildmode=plugin -o $plugin_name \
    && mv $plugin_name $PLUGIN_SOURCE_PATH
