#!/bin/bash

set -e

benchRegex=${1:-.}

go test -run=NONE -bench=$benchRegex || fatal "go test -run=NONE -bench=$benchRegex"