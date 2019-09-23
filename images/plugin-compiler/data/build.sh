#!/bin/bash

set -xe
# This directory will contain the plugin source and will be
# mounted from the host box by the user using docker volumes
PLUGIN_BUILD_PATH=/go/src/plugin-build

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

# Handle if plugin has own vendor folder, and ignore error if not
yes | cp -r $PLUGIN_BUILD_PATH/vendor $GOPATH/src || true
rm -rf $PLUGIN_BUILD_PATH/vendor

# Move GW vendor folder to GOPATH (same step should be made during building main binaries)
yes | cp -r $TYK_GW_PATH/vendor $GOPATH/src
rm -rf $TYK_GW_PATH/vendor

cd $PLUGIN_BUILD_PATH && \
    go build -buildmode=plugin -o $plugin_name
