#!/bin/bash
set -e

export PLUGIN_SOURCE_PATH=./basic-plugin
export TYK_GW_PATH=$(readlink -f ../../../..)

SOURCE_VERSION=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' $TYK_GW_PATH/gateway/version.go)

export GITHUB_TAG=${GITHUB_TAG:-$SOURCE_VERSION}

echo $GITHUB_TAG

./build.sh plugin.so