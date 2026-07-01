#!/usr/bin/env bash
# loadtest-gate.sh <compiler_image> [edition] [goarch] [symbol]
#
# The publish gate: build the upstream test-plugin with the freshly-built COMPILER,
# then verify it actually LOADS using the Gateway self-test binary baked into the
# compiler image and the Gateway's own
# `tyk plugin load -s <symbol>` command (the official verification from the docs).
# This triggers plugin.Open + symbol lookup - i.e. the real ABI/version check -
# without needing redis/compose/HTTP. Non-zero exit => do NOT publish.
#
# Runs on the runner's native arch (amd64 / arm64 via native runners). ABI/dependency
# alignment is arch-independent, but we gate both architectures anyway (belt & braces).
set -euo pipefail

COMPILER="${1:?usage: loadtest-gate.sh <compiler_image> [edition] [goarch] [symbol]}"
EDITION="${2:-ce}"                   # ce | ee | ee-fips
GOARCH="${3:-}"                      # empty -> native host arch; else cross target (e.g. s390x)
SYMBOL="${4:-AddFooBarHeader}"       # exported symbol in the test-plugin
PLUGDIR="$(mktemp -d)"
trap 'rm -rf "$PLUGDIR"' EXIT

cat > "$PLUGDIR/go.mod" <<'EOF'
module github.com/TykTechnologies/tyk/ci/tests/plugin-compiler-ng/testplugin

go 1.22

require (
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/TykTechnologies/tyk v1.9.2-0.20230606201232-e599d84bdfd1
	github.com/kr/pretty v0.2.1
)

replace github.com/jensneuse/graphql-go-tools => github.com/TykTechnologies/graphql-go-tools v1.6.2-0.20210609111804-af8c15678972
EOF

cat > "$PLUGDIR/main.go" <<'EOF'
package main

import (
	"net/http"

	"github.com/Masterminds/sprig/v3"
	"github.com/kr/pretty"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
)

var logger = log.Get()

// AddFooBarHeader adds custom "Foo: Bar" header to the request.
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
	logger.Info("Test")

	api := ctx.GetDefinition(r)
	if api != nil {
		logger.Info("API Definition", pretty.Sprint(api))
	}

	_ = sprig.FuncMap()
}

func main() {}
EOF

archenv=(); platform=()
if [ -n "$GOARCH" ]; then archenv=(-e GOARCH="$GOARCH"); platform=(--platform "linux/$GOARCH"); fi
# Optional: pin the COMPILER's own runtime platform (e.g. exercise the amd64 image under QEMU on an
# arm64 host). Default empty = run the compiler on the host's native arch. CI never sets it.
cplat=(); [ -n "${COMPILER_PLATFORM:-}" ] && cplat=(--platform "$COMPILER_PLATFORM")
echo "== gate: building test-plugin with $COMPILER (EDITION=$EDITION GOARCH=${GOARCH:-native} compiler=${COMPILER_PLATFORM:-native}) =="
docker run --rm -e EDITION="$EDITION" ${archenv[@]+"${archenv[@]}"} ${cplat[@]+"${cplat[@]}"} -v "$PLUGDIR:/plugin-source" "$COMPILER" plugin.so
SO="$(ls "$PLUGDIR"/plugin_*_linux_*.so | head -1)"
[ -f "$SO" ] || { echo "GATE FAIL: compiler produced no .so"; exit 1; }

if [ "${VALIDATE_ONLY:-0}" = "1" ]; then
  echo "GATE PASS: plugin built and validated by $COMPILER (EDITION=$EDITION GOARCH=${GOARCH:-native}); skipping plugin load because VALIDATE_ONLY=1"
  exit 0
fi

echo "== gate: '$COMPILER' self-test Gateway (linux/${GOARCH:-host}) tyk plugin load -s $SYMBOL =="
out="$(docker run --rm ${platform[@]+"${platform[@]}"} --entrypoint /usr/local/bin/tyk \
        -v "$SO:/gate-plugin.so:ro" "$COMPILER" \
        plugin load -f /gate-plugin.so -s "$SYMBOL" 2>&1)" && rc=0 || rc=$?
echo "$out"
if [ "${rc:-1}" = "0" ] && echo "$out" | grep -q "loaded ok"; then
  echo "GATE PASS: plugin built by $COMPILER loaded into its self-test Gateway (symbol $SYMBOL)"
else
  echo "GATE FAIL: plugin did not load into the self-test Gateway"
  echo "$out" | grep -iE "different version|plugin.Open|error" | head -3
  exit 1
fi
