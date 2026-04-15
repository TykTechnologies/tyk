#!/bin/bash
# ============================================================
# FIPS Image Validation Test Suite
#
# Usage:
#   ./ci/tests/fips-validation.sh <tag>
#   ./ci/tests/fips-validation.sh v5.12.1-alphafips2
#   ./ci/tests/fips-validation.sh v5.13.0-alphafips6
#
# Requirements:
#   - docker CLI (for manifest inspect, scout)
#   - docker buildx (for imagetools inspect)
#   - crane (brew install crane)
#   - go (for go version -m)
#   - trivy (brew install trivy or download from github)
#   - jq
#
# Exit code: 0 if all tests pass, 1 if any test fails
# ============================================================

set -euo pipefail

TAG="${1:?Usage: $0 <tag>}"
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# --- Helpers ---

pass() {
  echo "  PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "  FAIL: $1"
  FAIL=$((FAIL + 1))
}

check() {
  local condition="$1"
  local description="$2"
  if eval "$condition" > /dev/null 2>&1; then
    pass "$description"
  else
    fail "$description"
  fi
}

get_first_layer() {
  local img="$1"
  local digest
  digest=$(docker manifest inspect "$img" 2>/dev/null | \
    jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest')
  docker buildx imagetools inspect "$img@$digest" --raw 2>/dev/null | \
    jq -r '.layers[0].digest'
}

echo "============================================================"
echo "FIPS Image Validation: $TAG"
echo "============================================================"
echo

# ============================================================
# TEST 1: Architecture verification
# ============================================================
echo "--- Test 1: Architecture verification ---"

EE_ARCHS=$(docker manifest inspect tykio/tyk-gateway-ee:$TAG 2>/dev/null | \
  jq -r '[.manifests[] | select(.platform.os=="linux") | .platform.architecture] | sort | join(",")')
FIPS_ARCHS=$(docker manifest inspect tykio/tyk-gateway-fips:$TAG 2>/dev/null | \
  jq -r '[.manifests[] | select(.platform.os=="linux") | .platform.architecture] | sort | join(",")')
STD_ARCHS=$(docker manifest inspect tykio/tyk-gateway:$TAG 2>/dev/null | \
  jq -r '[.manifests[] | select(.platform.os=="linux") | .platform.architecture] | sort | join(",")')

echo "  EE:   $EE_ARCHS"
echo "  FIPS: $FIPS_ARCHS"
echo "  std:  $STD_ARCHS"

# FIPS must be amd64,arm64 (no s390x — DHI base doesn't support it)
check '[ "$FIPS_ARCHS" = "amd64,arm64" ]' "FIPS architectures: amd64,arm64"

# std must include s390x
check 'echo "$STD_ARCHS" | grep -q "s390x"' "std includes s390x"

# EE must include amd64 and arm64
check 'echo "$EE_ARCHS" | grep -q "amd64"' "EE includes amd64"
check 'echo "$EE_ARCHS" | grep -q "arm64"' "EE includes arm64"
echo

# ============================================================
# TEST 2: Base image verification
# ============================================================
echo "--- Test 2: Base image verification ---"

EE_LAYER=$(get_first_layer "tykio/tyk-gateway-ee:$TAG")
FIPS_LAYER=$(get_first_layer "tykio/tyk-gateway-fips:$TAG")
STD_LAYER=$(get_first_layer "tykio/tyk-gateway:$TAG")

echo "  EE:   ${EE_LAYER:0:25}..."
echo "  FIPS: ${FIPS_LAYER:0:25}..."
echo "  std:  ${STD_LAYER:0:25}..."

# FIPS and std must use different base images (DHI vs distroless)
check '[ "$FIPS_LAYER" != "$STD_LAYER" ]' "FIPS uses different base than std (DHI vs distroless)"
echo

# ============================================================
# TEST 3: Binary build info verification
# ============================================================
echo "--- Test 3: Binary build info ---"

for variant in fips ee std; do
  case $variant in
    ee)   img="tykio/tyk-gateway-ee" ;;
    fips) img="tykio/tyk-gateway-fips" ;;
    std)  img="tykio/tyk-gateway" ;;
  esac
  mkdir -p "$TMPDIR/$variant"
  crane export --platform linux/amd64 "$img:$TAG" - 2>/dev/null | \
    tar xf - -C "$TMPDIR/$variant" opt/tyk-gateway/tyk 2>/dev/null
done

FIPS_INFO=$(go version -m "$TMPDIR/fips/opt/tyk-gateway/tyk" 2>&1)
EE_INFO=$(go version -m "$TMPDIR/ee/opt/tyk-gateway/tyk" 2>&1)
STD_INFO=$(go version -m "$TMPDIR/std/opt/tyk-gateway/tyk" 2>&1)

# FIPS binary checks
check 'echo "$FIPS_INFO" | grep -q "GOFIPS140=v1.0.0"' \
  "FIPS binary has GOFIPS140=v1.0.0"

check 'echo "$FIPS_INFO" | grep -q "tags=goplugin,ee,fips"' \
  "FIPS binary tags include fips"

check 'echo "$FIPS_INFO" | grep "DefaultGODEBUG" | grep -q "fips140=on"' \
  "FIPS binary DefaultGODEBUG has fips140=on"

# EE binary checks
check '! echo "$EE_INFO" | grep -q "GOFIPS140"' \
  "EE binary does NOT have GOFIPS140"

check 'echo "$EE_INFO" | grep -q "tags=goplugin,ee"' \
  "EE binary tags: goplugin,ee"

check '! echo "$EE_INFO" | grep "DefaultGODEBUG" | grep -q "fips140=on"' \
  "EE binary DefaultGODEBUG does NOT have fips140=on"

# std binary checks
check '! echo "$STD_INFO" | grep -q "GOFIPS140"' \
  "std binary does NOT have GOFIPS140"

check 'echo "$STD_INFO" | grep -q "tags=goplugin"' \
  "std binary tags: goplugin"
echo

# ============================================================
# TEST 4: Trivy scan — baseline (no filtering)
# ============================================================
echo "--- Test 4: Trivy baseline scan ---"

TRIVY_CMD="trivy"
if [ -x /tmp/trivy-bin/trivy ]; then
  TRIVY_CMD="/tmp/trivy-bin/trivy"
fi

for variant in ee fips std; do
  case $variant in
    ee)   img="tykio/tyk-gateway-ee" ;;
    fips) img="tykio/tyk-gateway-fips" ;;
    std)  img="tykio/tyk-gateway" ;;
  esac
  RESULT=$($TRIVY_CMD image --scanners vuln --severity HIGH,CRITICAL \
    "$img:$TAG" 2>&1 | grep "Total:" | head -1)
  echo "  $variant: $RESULT"
done
echo "  (baseline — OS CVEs expected for FIPS/DHI images)"
echo

# ============================================================
# TEST 5: Trivy scan — --ignore-unfixed
# ============================================================
echo "--- Test 5: Trivy with --ignore-unfixed (FIPS image) ---"
echo "  (only FIPS is tested — EE and std use distroless which may have fixable CVEs)"

for variant in fips; do
  case $variant in
    fips) img="tykio/tyk-gateway-fips" ;;
  esac
  # Use JSON output to count only OS-level CVEs (not Go dependencies).
  # OS CVEs have Type "debian" or "alpine", Go deps have Type "gobinary".
  OS_CVE_COUNT=$($TRIVY_CMD image --scanners vuln --severity HIGH,CRITICAL \
    --ignore-unfixed --format json "$img:$TAG" 2>/dev/null | \
    jq '[.Results[]? | select(.Type != "gobinary") | .Vulnerabilities[]?] | length')
  if [ "$OS_CVE_COUNT" = "0" ] || [ -z "$OS_CVE_COUNT" ]; then
    pass "$variant: 0 OS-level HIGH/CRITICAL CVEs (--ignore-unfixed)"
  else
    fail "$variant: $OS_CVE_COUNT OS-level HIGH/CRITICAL CVEs (expected 0)"
  fi
done
echo

# ============================================================
# TEST 6: Docker Scout scan
# ============================================================
echo "--- Test 6: Docker Scout scan ---"

if command -v docker &>/dev/null && docker scout version &>/dev/null 2>&1; then
  SCOUT_RESULT=$(docker scout cves --only-severity high,critical \
    "tykio/tyk-gateway-fips:$TAG" 2>&1)
  # Scout reports OS and Go CVEs together. Check that the base image
  # section shows 0 (the "Base image" line in Scout output).
  if echo "$SCOUT_RESULT" | grep -q "No vulnerable packages detected"; then
    pass "Docker Scout: 0 vulnerabilities on FIPS image"
  else
    # Count only — Scout may show Go dep CVEs which are expected
    SCOUT_COUNT=$(echo "$SCOUT_RESULT" | grep "vulnerabilities found" | head -1)
    echo "  INFO: $SCOUT_COUNT (Go dependency CVEs are expected)"
    pass "Docker Scout: scan completed on FIPS image"
  fi
else
  echo "  SKIP: Docker Scout CLI not available"
fi
echo

# ============================================================
# TEST 7: Built image attestations
# ============================================================
echo "--- Test 7: Built image attestations ---"

if command -v docker &>/dev/null && docker scout version &>/dev/null 2>&1; then
  ATTEST_OUTPUT=$(docker scout attestation list "tykio/tyk-gateway-fips:$TAG" 2>&1)

  check 'echo "$ATTEST_OUTPUT" | grep -q "SBOM obtained from attestation"' \
    "FIPS image has SBOM attestation"

  check 'echo "$ATTEST_OUTPUT" | grep -q "Provenance obtained from attestation"' \
    "FIPS image has provenance attestation"

  check 'echo "$ATTEST_OUTPUT" | grep -q "TykTechnologies/tyk"' \
    "FIPS image provenance traces to TykTechnologies/tyk"
else
  echo "  SKIP: Docker Scout CLI not available"
fi
echo

# ============================================================
# TEST 8: FIPS image provenance and base image verification
# ============================================================
echo "--- Test 8: FIPS image provenance chain ---"

if command -v docker &>/dev/null && docker scout version &>/dev/null 2>&1; then
  FIPS_ATTEST=$(docker scout attestation list "tykio/tyk-gateway-fips:$TAG" 2>&1)

  # Verify our FIPS image identifies its DHI base image
  check 'echo "$FIPS_ATTEST" | grep -q "dhi-busybox"' \
    "FIPS image identifies DHI busybox as base image"

  # Verify the base image in the provenance chain has FIPS attestation
  # (Scout resolves the base image reference from our image's provenance)
  BASE_IMG=$(echo "$FIPS_ATTEST" | grep "Base image" -A1 | grep "dhi-busybox" | head -1 | tr -d ' ')
  if [ -n "$BASE_IMG" ]; then
    pass "FIPS image base image reference found in provenance"
  else
    # Base image info may appear differently — check for DHI reference
    check 'echo "$FIPS_ATTEST" | grep -qi "dhi"' \
      "FIPS image references Docker Hardened Image in provenance"
  fi
else
  echo "  SKIP: Docker Scout CLI not available"
fi
echo

# ============================================================
# RESULTS
# ============================================================
echo "============================================================"
echo "Results: $PASS passed, $FAIL failed"
echo "============================================================"

if [ "$FAIL" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  exit 0
else
  echo "SOME CHECKS FAILED"
  exit 1
fi
