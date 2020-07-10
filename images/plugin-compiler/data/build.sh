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

# Handle if plugin has own vendor folder, and ignore error if not
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true
yes | cp -r $PLUGIN_BUILD_PATH/vendor $GOPATH/src || true \
        && rm -rf $PLUGIN_BUILD_PATH/vendor

cd $PLUGIN_BUILD_PATH \
    && go build -buildmode=plugin -ldflags "-pluginpath=$plugin_path" -o $plugin_name \
    && mv $plugin_name $PLUGIN_SOURCE_PATH
