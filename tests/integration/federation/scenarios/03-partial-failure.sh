#!/usr/bin/env bash
# Scenario 03 — Apollo-spec partial failure (Cast 3).
#
# Same REST topology as Cast 1, but issues a query that resolves three
# representations: ids 1 (ok) and 2 (ok) round-trip a User, while id 99
# misses (mock returns 404). The expected response shape is
# `_entities[i] = null` for the failure with a path-tagged error in the
# top-level `errors` array. The supergraph view is the equivalent at the
# parent-field level: the post whose author id is 99 surfaces a null
# author with a corresponding error entry.
#
# Three sample queries are dispatched (id=1 ok, id=99 fail, id=2 ok)
# directly against Tyk's `_entities` to make the per-entity behaviour
# visible without the router redacting it.
set -euo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_lib.sh
source "$SCENARIO_DIR/_lib.sh"

trap trap_cleanup EXIT

require_bin go
require_bin curl

WORK="$(mktemp -d)"
TMPS+=("$WORK")

start_runner partial-failure "$WORK/runner.log"
TYK_URL="$(extract_kv "$WORK/runner.log" TYK_URL)"

ENTITIES_QUERY='{
  "query": "query($r: [_Any!]!) { _entities(representations: $r) { ... on User { id username } } }",
  "variables": {"r":[{"__typename":"User","id":"1"},{"__typename":"User","id":"99"},{"__typename":"User","id":"2"}]}
}'

echo "Sending three representations (id=1 ok, id=99 missing, id=2 ok) to Tyk."
RESPONSE="$(gql_query "$TYK_URL" "$ENTITIES_QUERY")"
echo "$RESPONSE"

# Spec compliance: alice and bob should round-trip; id=99 should appear
# as a null in the `_entities` array with an error in the top-level
# errors list whose path points at the failed index.
for needle in '"username":"alice"' '"username":"bob"' '"_entities"' 'null'; do
  if ! grep -q "$needle" <<<"$RESPONSE"; then
    echo "expected $needle in response, got:" >&2
    echo "$RESPONSE" >&2
    exit 1
  fi
done

if ! grep -q '"errors"' <<<"$RESPONSE"; then
  echo "expected partial-failure errors array, got:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi
