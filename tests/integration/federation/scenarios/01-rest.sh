#!/usr/bin/env bash
# Scenario 01 — REST upstream UDG federation (Cast 1).
#
# Stands up a Tyk gateway in --scenario=rest mode (REST upstream returning
# `{"id":"1","username":"alice"}`), a Python stub subgraph that owns Post,
# composes them with rover, runs Apollo Router, and asks for a Post +
# its author.username — proving that the router fans out from the stub's
# entity reference back into Tyk for the User.
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
start_runner rest "$WORK/runner.log"

export TYK_URL="$(extract_kv "$WORK/runner.log" TYK_URL)"
export STUB_URL="http://127.0.0.1:${STUB_PORT}"

compose_supergraph "$HARNESS_DIR/compose/rest.yaml" "$WORK/supergraph.graphql"
start_router "$WORK/supergraph.graphql" "127.0.0.1:${ROUTER_PORT}" "$WORK/router.log"

QUERY='{"query":"{ posts { id title author { id username } } }"}'
RESPONSE="$(gql_query "http://127.0.0.1:${ROUTER_PORT}/" "$QUERY")"
echo "$RESPONSE"

if ! grep -q '"username":"alice"' <<<"$RESPONSE"; then
  echo "expected alice's username in the response, got:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi
