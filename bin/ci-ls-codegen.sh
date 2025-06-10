#!/usr/bin/env bash
#
# ci-find-codegen.sh
#
# Walks the current directory and lists all Go files containing the "Code generated" marker.
# Adjust the GREP_PATTERN if your generated files use a different header.

set -euo pipefail

# 1) Root directory to start from (default: current directory)
ROOT_DIR="${1:-.}"

# 2) Grep pattern to identify generated-code comments.
#    Most Go generators use: "// Code generated .* DO NOT EDIT."
GREP_PATTERN='^// Code generated.*DO NOT EDIT\.'

echo "Searching for generated-code markers in Go files under: $ROOT_DIR"
echo

# Find only .go files and grep for the marker
find "$ROOT_DIR" -type f -name '*.go' -print0 \
  | xargs -0 grep -I -l -E "$GREP_PATTERN"

