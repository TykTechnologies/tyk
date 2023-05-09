#!/bin/bash
set -e

export PLUGIN_SOURCE_PATH=./basic-plugin
export TYK_GW_PATH=$(readlink -f ../../../..)

./build.sh plugin.so