#!/bin/bash
set -e

if [ -z "$GITHUB_TAG" ]; then
    echo "Need GITHUB_TAG env"
    exit 1
fi

export PLUGIN_SOURCE_PATH=./basic-plugin
export TYK_GW_PATH=$(readlink -f ../../../..)

./build.sh plugin.so