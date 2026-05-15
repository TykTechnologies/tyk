#!/usr/bin/env bash
# Scenario 04 — proxy-mode passthrough (Cast 4).
#
# Tyk runs in proxyOnly mode in front of the in-process federated mock
# subgraph that the runner stands up internally. From the Apollo Router's
# perspective the subgraph IS Tyk; Tyk just augments the SDL with the v2
# @link directive and forwards `_entities` queries verbatim.
#
# Expected response (formatting may vary):
#   {"data":{"_entities":[{"id":"1","username":"alice"}]}}
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

ROUTER_PORT="$(pick_free_port)"

start_runner proxy "$WORK/runner.log"
export TYK_URL="$(extract_kv "$WORK/runner.log" TYK_URL)"

compose_supergraph "$HARNESS_DIR/compose/proxy.yaml" "$WORK/supergraph.graphql"
start_router "$WORK/supergraph.graphql" "127.0.0.1:${ROUTER_PORT}" "$WORK/router.log"

QUERY='{"query":"query($r: [_Any!]!) { _entities(representations: $r) { ... on User { id username } } }","variables":{"r":[{"__typename":"User","id":"1"}]}}'
RESPONSE="$(gql_query "http://127.0.0.1:${ROUTER_PORT}/" "$QUERY")"
echo "$RESPONSE"

if ! grep -q '"username":"alice"' <<<"$RESPONSE"; then
  echo "expected alice's username in the response, got:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi
