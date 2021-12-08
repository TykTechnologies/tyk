#!/bin/bash

plugin_name=$1
PLUGIN_SOURCE_PATH=${PLUGIN_SOURCE_PATH:-/plugin-source}
PLUGIN_BUILD_PATH=${PLUGIN_BUILD_PATH:-/go/src/plugin-build}

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

cd $PLUGIN_SOURCE_PATH
# Handle if plugin has own vendor folder, and ignore error if not
if [ ! -f go.mod ]; then
    echo 'Please use gomodules.'
    exit 1
fi

[ -d ./vendor ] && echo 'Found vendor directory, ignoring'

go build -buildmode=plugin -o $plugin_name && go mod tidy
