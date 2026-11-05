#!/usr/bin/env bash
# Generates Go, Java, TypeScript and Python clients from a swagger with the
# configs in this directory and builds each one. Any failure exits 1.
#
# Usage: ci/codegen/check.sh [swagger.yml]
# Needs java, mvn, go, node/npm and python3 on PATH. Downloads the generator
# jar once into ${XDG_CACHE_HOME:-$HOME/.cache}/tyk-codegen. Set MVN to use a
# different Maven command (for example one that runs in a container).
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SPEC=$(realpath "${1:-swagger.yml}")
GENERATOR_VERSION=7.26.0
GENERATOR_SHA256=1760050094997b9cc790cc1350be095f15da8c08a996b184d3eadc4ccda5e35e
MVN=${MVN:-mvn}
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/tyk-codegen
JAR=$CACHE/openapi-generator-cli-$GENERATOR_VERSION.jar
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

fail() { echo "::error::$1"; FAILED=1; }

fetch_jar() {
  if [ ! -f "$JAR" ]; then
    mkdir -p "$CACHE"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$JAR.tmp" "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/$GENERATOR_VERSION/openapi-generator-cli-$GENERATOR_VERSION.jar" \
      && mv "$JAR.tmp" "$JAR"
  fi
  echo "$GENERATOR_SHA256  $JAR" | sha256sum -c --quiet || { echo "openapi-generator jar checksum mismatch"; exit 1; }
}

generate() {
  java -jar "$JAR" generate -i "$SPEC" -c "$HERE/$1.yaml" -o "$WORK/$1" > "$WORK/$1.gen.log" 2>&1 \
    || { fail "$1: generation failed"; tail -20 "$WORK/$1.gen.log"; return 1; }
}

build() {
  local lang=$1; shift
  (cd "$WORK/$lang" && "$@") > "$WORK/$lang.build.log" 2>&1 \
    || { fail "$lang: build failed"; grep -E "error|Error" "$WORK/$lang.build.log" | head -40; tail -5 "$WORK/$lang.build.log"; }
}

fetch_jar

echo "== go"
generate go && GOWORK=off GOFLAGS=-mod=mod build go go build -gcflags=-e ./...

echo "== java"
generate java && build java "$MVN" -q -B -DskipTests -Dmaven.compiler.maxerrs=1000 compile

echo "== typescript"
generate typescript && build typescript sh -c 'npm install --silent --no-save axios typescript@7 && npx tsc --noEmit --skipLibCheck --target es2019 --module esnext --moduleResolution bundler ./*.ts'

echo "== python"
generate python && build python sh -c 'python3 -m venv .venv && .venv/bin/pip install --quiet pydantic python-dateutil urllib3 typing-extensions && .venv/bin/python -c "import sys; sys.path.insert(0, \".\"); import openapi_client"'

if [ "$FAILED" = 0 ]; then echo "codegen check passed for $SPEC"; else echo "codegen check failed for $SPEC"; fi
exit "$FAILED"
