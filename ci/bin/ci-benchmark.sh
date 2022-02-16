#!/bin/bash

set -e

benchRegex=${1:-.}

TYK_LOGLEVEL= go test -run=NONE -bench=$benchRegex || fatal "go test -run=NONE -bench=$benchRegex"
