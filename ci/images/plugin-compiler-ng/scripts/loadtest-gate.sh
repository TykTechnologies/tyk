#!/usr/bin/env bash
# loadtest-gate.sh <compiler_image> [edition] [goarch] [symbol]
#
# The publish gate: build the upstream test-plugin with the freshly-built COMPILER,
# then verify it actually LOADS using the Gateway self-test binary baked into the
# compiler image and the Gateway's own
# `tyk plugin load -s <symbol>` command (the official verification from the docs).
# Native builds then start an isolated Gateway, Redis, and echo upstream, load the
# plugin in an API, make an HTTP request, and require AddFooBarHeader to add Foo: Bar.
# Non-zero exit => do NOT publish.
#
# The HTTP/load gate runs only on the runner's native architecture. Cross targets are
# still compiled and statically validated, but are not loaded without native execution.
set -euo pipefail

COMPILER="${1:?usage: loadtest-gate.sh <compiler_image> [edition] [goarch] [symbol]}"
EDITION="${2:-ce}"                   # ce | ee | ee-fips
GOARCH="${3:-}"                      # empty -> native host arch; else cross target (e.g. s390x)
SYMBOL="${4:-AddFooBarHeader}"       # exported symbol in the test-plugin
PLUGDIR="$(mktemp -d)"
NETWORK=""
REDIS_CONTAINER=""
UPSTREAM_CONTAINER=""
GATEWAY_CONTAINER=""

cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ] && [ -n "$GATEWAY_CONTAINER" ]; then
    docker logs "$GATEWAY_CONTAINER" 2>&1 || true
  fi
  [ -z "$GATEWAY_CONTAINER" ] || docker rm -f "$GATEWAY_CONTAINER" >/dev/null 2>&1 || true
  [ -z "$UPSTREAM_CONTAINER" ] || docker rm -f "$UPSTREAM_CONTAINER" >/dev/null 2>&1 || true
  [ -z "$REDIS_CONTAINER" ] || docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
  [ -z "$NETWORK" ] || docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -rf "$PLUGDIR"
  exit "$rc"
}
trap cleanup EXIT

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
  echo "GATE PASS: plugin built and validated by $COMPILER (EDITION=$EDITION GOARCH=${GOARCH:-native}); skipping native load/HTTP gate because VALIDATE_ONLY=1"
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

mkdir -p "$PLUGDIR/apps"
cat > "$PLUGDIR/upstream.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, r.Header.Get("Foo"))
	})
	if err := http.ListenAndServe(":8081", nil); err != nil {
		panic(err)
	}
}
EOF

cat > "$PLUGDIR/tyk.conf" <<'EOF'
{
  "listen_address": "0.0.0.0",
  "listen_port": 8080,
  "secret": "plugin-compiler-ng-gate",
  "template_path": "/go/src/github.com/TykTechnologies/tyk/templates",
  "use_db_app_configs": false,
  "app_path": "/gate/apps",
  "middleware_path": "/gate/middleware",
  "storage": {
    "type": "redis",
    "host": "redis",
    "port": 6379
  },
  "enable_analytics": false,
  "dns_cache": {
    "enabled": false
  },
  "allow_master_keys": false,
  "policies": {
    "policy_source": "file"
  },
  "hash_keys": true
}
EOF

cat > "$PLUGDIR/apps/plugin-gate.json" <<'EOF'
{
  "name": "Plugin compiler NG behavior gate",
  "slug": "plugin-compiler-ng-gate",
  "api_id": "plugin-compiler-ng-gate",
  "org_id": "plugin-compiler-ng-gate",
  "use_keyless": true,
  "version_data": {
    "not_versioned": true,
    "versions": {
      "Default": {
        "name": "Default",
        "use_extended_paths": true
      }
    }
  },
  "proxy": {
    "listen_path": "/plugin-gate/",
    "target_url": "http://upstream:8081/",
    "strip_listen_path": true
  },
  "auth": {
    "auth_header_name": "Authorization"
  },
  "custom_middleware": {
    "pre": [],
    "post": [
      {
        "name": "AddFooBarHeader",
        "path": "/gate/plugin.so",
        "require_session": false
      }
    ],
    "post_key_auth": [],
    "auth_check": {},
    "response": [],
    "driver": "goplugin"
  }
}
EOF

run_token="$(printf '%s-%s-%s' "${GITHUB_RUN_ID:-local}" "${GITHUB_RUN_ATTEMPT:-0}" "$RANDOM" | tr -cd '[:alnum:]-')"
NETWORK="plugin-compiler-ng-gate-$run_token"
REDIS_CONTAINER="pcng-redis-$run_token"
UPSTREAM_CONTAINER="pcng-upstream-$run_token"
GATEWAY_CONTAINER="pcng-gateway-$run_token"

docker network create "$NETWORK" >/dev/null
docker run --detach --name "$REDIS_CONTAINER" --network "$NETWORK" --network-alias redis \
  redis:6.0-alpine@sha256:2b35fc7d2908e25aa6aa197f97882c8a67829d3b106ad5ea5c8028f816f26aa8 >/dev/null
docker run --detach --name "$UPSTREAM_CONTAINER" --network "$NETWORK" --network-alias upstream \
  --entrypoint /usr/local/go/bin/go \
  -v "$PLUGDIR/upstream.go:/gate/upstream.go:ro" \
  "$COMPILER" run /gate/upstream.go >/dev/null

for _ in $(seq 1 30); do
  if [ "$(docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null || true)" = "PONG" ]; then
    break
  fi
  sleep 1
done
test "$(docker exec "$REDIS_CONTAINER" redis-cli ping)" = "PONG"

docker run --detach --name "$GATEWAY_CONTAINER" --network "$NETWORK" \
  --publish 127.0.0.1::8080 \
  --entrypoint /usr/local/bin/tyk \
  -v "$SO:/gate/plugin.so:ro" \
  -v "$PLUGDIR/tyk.conf:/gate/tyk.conf:ro" \
  -v "$PLUGDIR/apps:/gate/apps:ro" \
  "$COMPILER" --conf=/gate/tyk.conf >/dev/null

gateway_port="$(docker port "$GATEWAY_CONTAINER" 8080/tcp | sed -n 's/.*://p' | head -1)"
test -n "$gateway_port"
response=""
for _ in $(seq 1 60); do
  if ! docker inspect --format '{{.State.Running}}' "$GATEWAY_CONTAINER" 2>/dev/null | grep -qx true; then
    break
  fi
  if response="$(curl --fail --silent --show-error "http://127.0.0.1:${gateway_port}/plugin-gate/" 2>/dev/null)" &&
     [ "$response" = "Bar" ]; then
    echo "GATE PASS: AddFooBarHeader changed the proxied request (Foo: Bar) for EDITION=$EDITION"
    exit 0
  fi
  sleep 1
done

echo "GATE FAIL: isolated Gateway request did not observe AddFooBarHeader behavior (response='$response')" >&2
exit 1
