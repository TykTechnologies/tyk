#!/usr/bin/env bash
# Scenario 05 — Tyk in BOTH positions inside one supergraph (Cast 5).
#
# Two Tyk runners are spun up:
#   - users:  --scenario=rest   (UDG/REST upstream owning the User entity)
#   - posts:  --scenario=proxy  (proxyOnly fronting the Python stub
#                                 federation subgraph)
#
# Apollo Router sees two subgraphs, both backed by Tyk. The query asks
# for posts and traverses author back to the users subgraph.
#
# Expected response (formatting may vary):
#   {"data":{"posts":[{"id":"p1","title":"First post","author":{"id":"1","username":"alice"}}, ...]}}
set -euo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCENARIO_DIR/_lib.sh"

trap trap_cleanup EXIT

require_bin go
require_bin rover
require_bin apollo-router
require_bin envsubst
require_bin curl

WORK="$(mktemp -d)"
TMPS+=("$WORK")

STUB_PORT="$(pick_free_port)"
ROUTER_PORT="$(pick_free_port)"

start_stub "$STUB_PORT" "$WORK/stub.log"

# users subgraph — Tyk #1, REST-backed UDG.
start_runner rest "$WORK/runner-users.log"
export TYK_URL="$(extract_kv "$WORK/runner-users.log" TYK_URL)"

# posts subgraph — Tyk #2, proxyOnly fronting the Python stub. The
# runner reads TYK_PROXY_TARGET from the environment so we can wire it
# at the stub's URL. Pass the env via the variadic prefix supported by
# start_runner so it survives the background subshell.
start_runner proxy "$WORK/runner-proxy.log" env TYK_PROXY_TARGET="http://127.0.0.1:${STUB_PORT}"
export TYK_PROXY_URL="$(extract_kv "$WORK/runner-proxy.log" TYK_URL)"

compose_supergraph "$HARNESS_DIR/compose/both-positions.yaml" "$WORK/supergraph.graphql"
start_router "$WORK/supergraph.graphql" "127.0.0.1:${ROUTER_PORT}" "$WORK/router.log"

QUERY='{"query":"{ posts { id title author { id username } } }"}'
RESPONSE="$(gql_query "http://127.0.0.1:${ROUTER_PORT}/" "$QUERY")"
echo "$RESPONSE"

if ! grep -q '"username":"alice"' <<<"$RESPONSE"; then
  echo "expected alice's username in the response, got:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi
