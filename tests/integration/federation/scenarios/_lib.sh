# Shared helpers for the federation reproduction scenario scripts.
# Sourced (not executed) by the per-scenario scripts. All functions here
# are POSIX-bash and assume `set -euo pipefail`.

# Resolve directories relative to this file so scripts can be invoked
# from any cwd.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_DIR="$(cd "$LIB_DIR/.." && pwd)"

# Tracks every PID we've spawned so trap_cleanup can kill them all.
PIDS=()

# Tracks every temp file/dir we've created so trap_cleanup can rm them.
TMPS=()

# trap_cleanup is wired via `trap trap_cleanup EXIT` by every scenario.
# It tries to terminate gracefully, then SIGKILLs anything still running.
trap_cleanup() {
  local code=$?
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    kill -TERM "${PIDS[@]}" 2>/dev/null || true
    sleep 0.5
    kill -KILL "${PIDS[@]}" 2>/dev/null || true
  fi
  if [[ ${#TMPS[@]} -gt 0 ]]; then
    rm -rf "${TMPS[@]}" 2>/dev/null || true
  fi
  exit "$code"
}

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required binary: $bin (see README.md for install instructions)" >&2
    exit 127
  fi
}

# wait_for_marker <fd-file> <marker-regex> [timeout-seconds]
# Tail a log file until a line matching the regex appears.
wait_for_marker() {
  local file="$1"
  local marker="$2"
  local timeout="${3:-30}"
  local elapsed=0
  while ! grep -Eq "$marker" "$file" 2>/dev/null; do
    sleep 0.2
    elapsed=$((elapsed + 1))
    if (( elapsed > timeout * 5 )); then
      echo "timed out waiting for /$marker/ in $file:" >&2
      tail -50 "$file" >&2 || true
      return 1
    fi
  done
}

# extract_kv <file> <key>
# Pull the first `KEY=value` line out of a log file and echo the value.
extract_kv() {
  local file="$1"
  local key="$2"
  grep -E "^${key}=" "$file" | head -1 | cut -d= -f2-
}

# build_runner ensures the runner binary is compiled. Idempotent — skips
# the build if the binary is already present and newer than main.go.
build_runner() {
  local out="$HARNESS_DIR/runner/runner"
  if [[ ! -x "$out" ]] || [[ "$HARNESS_DIR/runner/main.go" -nt "$out" ]]; then
    ( cd "$HARNESS_DIR/runner" && go build -o runner . )
  fi
  echo "$out"
}

# start_runner <scenario> <log-file> [extra-env=val ...]
# Launches the in-process Tyk runner in the background, recording its PID.
start_runner() {
  local scenario="$1"
  local log="$2"
  shift 2
  local runner_bin
  runner_bin="$(build_runner)"

  ( "$@" "$runner_bin" --scenario "$scenario" >"$log" 2>&1 ) &
  PIDS+=("$!")
  wait_for_marker "$log" "^READY$" 30
}

# start_stub <port> <log-file>
# Launches the Python stub subgraph on the given port.
start_stub() {
  local port="$1"
  local log="$2"
  local py
  py="$(command -v python3 || command -v python)"
  if [[ -z "$py" ]]; then
    echo "python3 not found on PATH" >&2
    return 127
  fi
  ( "$py" "$HARNESS_DIR/stub-subgraph/main.py" --port "$port" >"$log" 2>&1 ) &
  PIDS+=("$!")
  wait_for_marker "$log" "^READY$" 30
}

# pick_free_port — echo a TCP port that nothing is currently listening on.
# Uses bash /dev/tcp so we don't depend on `nc` or `lsof`.
pick_free_port() {
  local port
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    port=$(( (RANDOM % 20000) + 30000 ))
    if ! (echo > "/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
      echo "$port"
      return 0
    fi
  done
  echo "could not find a free port" >&2
  return 1
}

# compose_supergraph <compose-yaml> <out-graphql>
# Renders the compose YAML through envsubst, writes a temp file, and
# runs `rover supergraph compose` against it. The resulting supergraph
# schema is written to <out-graphql>.
compose_supergraph() {
  local compose="$1"
  local out="$2"
  local rendered
  rendered="$(mktemp)"
  TMPS+=("$rendered")
  envsubst < "$compose" > "$rendered"
  rover supergraph compose --config "$rendered" --elv2-license accept > "$out"
}

# start_router <supergraph> <listen-host:port> <log-file>
# Launches Apollo Router with the harness's router.yaml.
start_router() {
  local supergraph="$1"
  local listen="$2"
  local log="$3"
  ( APOLLO_TELEMETRY_DISABLED=1 \
    APOLLO_ELV2_LICENSE=accept \
    apollo-router \
      --supergraph "$supergraph" \
      --listen "$listen" \
      --config "$HARNESS_DIR/router/router.yaml" \
      >"$log" 2>&1 ) &
  PIDS+=("$!")
  # Apollo Router prints the listening address once it's accepting traffic.
  wait_for_marker "$log" "GraphQL endpoint exposed|listening on" 30
}

# gql_query <router-url> <query-json>
# POST a GraphQL query and echo the response body. Uses --fail-with-body
# so curl's exit code reflects HTTP status but we still see the body.
gql_query() {
  local url="$1"
  local body="$2"
  curl -sS -X POST -H 'content-type: application/json' --data "$body" "$url"
}
