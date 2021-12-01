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

if [ -d ./vendor ]; then
    echo 'Found vendor directory, ignoring'
else
    go mod vendor
fi
# We can't just copy Tyk dependencies on top of plugin dependencies, since different package versions have different file structures
# First we need to find which deps GW already has, remove this folders, and after copy fresh versions from GW

# github.com and rest of packages have different nesting levels, so have to handle it separately
ls -d $TYK_GW_PATH/vendor/github.com/*/* | sed "s|$TYK_GW_PATH/vendor|$(pwd)/vendor|g" | xargs -d '\n' rm -rf
ls -d $TYK_GW_PATH/vendor/*/* | sed "s|$TYK_GW_PATH/vendor|$(pwd)/vendor|g" | grep -v github | xargs -d '\n' rm -rf
cp ./vendor/modules.txt modules.txt.plugin

# Copy GW dependencies
yes | cp -rf $TYK_GW_PATH/vendor/* ./vendor
cp modules.txt.plugin ./vendor/modules.txt

go build -mod=mod -buildmode=plugin -o $plugin_name
