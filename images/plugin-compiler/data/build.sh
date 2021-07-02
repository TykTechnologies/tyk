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
[ -f $PLUGIN_BUILD_PATH/go.mod ] && go mod vendor
go build -buildmode=plugin -o $plugin_name \
    && mv $plugin_name $PLUGIN_SOURCE_PATH
