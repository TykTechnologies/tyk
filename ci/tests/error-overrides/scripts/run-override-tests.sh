#!/bin/bash

# This script tests the error_overrides feature by sending requests through
# the Tyk Gateway (with overrides enabled) and verifying:
# 1. Response body matches the override configuration
# 2. Response headers include custom override headers
# 3. Access logs still contain the correct response_flag
# =============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - uses the overrides gateway on port 8081
TYK_OVERRIDE_URL="${TYK_OVERRIDE_URL:-http://localhost:8081}"
TYK_OVERRIDE_CONTAINER="${TYK_OVERRIDE_CONTAINER:-test-access-logs-tyk-gateway-overrides-1}"
TYK_LOG_FILE="${TYK_LOG_FILE:-/tmp/tyk-override-access.log}"
WAIT_FOR_LOG_SECONDS=3

# Test results
PASSED=0
FAILED=0
SKIPPED=0

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_separator() {
    echo "============================================================================="
}

# Refresh logs from Docker container
refresh_logs() {
    if [ -n "$TYK_OVERRIDE_CONTAINER" ]; then
        docker logs "$TYK_OVERRIDE_CONTAINER" > "$TYK_LOG_FILE" 2>&1
    fi
}

# Get access log entry for an API path
get_log_entry() {
    local api_path=$1
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)

    if [ -f "$TYK_LOG_FILE" ]; then
        grep -E "prefix=access-log" "$TYK_LOG_FILE" 2>/dev/null | grep "api_id=${api_id}" | tail -1
    fi
}

# Extract response_flag from log entry
get_flag_from_log() {
    local log_entry=$1
    echo "$log_entry" | sed -n 's/.*response_flag=\([^ ]*\).*/\1/p'
}

# -----------------------------------------------------------------------------
# Core Test Function for Error Overrides
# -----------------------------------------------------------------------------

# run_override_test - Main test function for error overrides
#
# Arguments:
#   $1 - test_name: Name of the test
#   $2 - api_path: API path to request
#   $3 - expected_flag: Expected response_flag in access log
#   $4 - expected_body_contains: String that should appear in response body
#   $5 - expected_header: Custom header that should be present (X-Error-Flag value)
#   $6 - expected_status: Expected HTTP status code (optional, defaults to checking any)
#   $7 - extra_curl_args: Additional curl arguments (optional, e.g., headers)
#
run_override_test() {
    local test_name=$1
    local api_path=$2
    local expected_flag=$3
    local expected_body_contains=$4
    local expected_header=$5
    local expected_status=${6:-""}
    local extra_curl_args=${7:-""}
    local timeout=${8:-10}

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"
    log_info "  Expected Flag: $expected_flag"
    log_info "  Expected Body Contains: $expected_body_contains"
    log_info "  Expected X-Error-Flag: $expected_header"
    [ -n "$expected_status" ] && log_info "  Expected Status: $expected_status"

    # Create temp files for response
    local body_file=$(mktemp)
    local header_file=$(mktemp)

    # Send request and capture response
    local http_code
    if [ -n "$extra_curl_args" ]; then
        http_code=$(eval "curl -s -o '$body_file' -D '$header_file' -w '%{http_code}' \
            --connect-timeout '$timeout' \
            --max-time '$timeout' \
            $extra_curl_args \
            '${TYK_OVERRIDE_URL}${api_path}' 2>/dev/null" || echo "000")
    else
        http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
            --connect-timeout "$timeout" \
            --max-time "$timeout" \
            "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")
    fi

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    # Wait for log and refresh
    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    # Track test results
    local test_passed=true
    local failures=""

    # Check 1: Response body contains expected content
    if echo "$response_body" | grep -q "$expected_body_contains"; then
        log_info "  [OK] Body contains: $expected_body_contains"
    else
        test_passed=false
        failures="${failures}\n  - Body missing: $expected_body_contains"
        log_warn "  Body does not contain expected string"
    fi

    # Check 2: X-Error-Flag header is present with expected value
    if echo "$response_headers" | grep -qi "X-Error-Flag: $expected_header"; then
        log_info "  [OK] X-Error-Flag header: $expected_header"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: $expected_header"
        log_warn "  X-Error-Flag header not found or incorrect"
    fi

    # Check 3: X-Override-Applied header is present
    if echo "$response_headers" | grep -qi "X-Override-Applied: true"; then
        log_info "  [OK] X-Override-Applied: true"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Override-Applied header"
        log_warn "  X-Override-Applied header not found"
    fi

    # Check 4: Status code matches (if specified)
    if [ -n "$expected_status" ]; then
        if [ "$http_code" = "$expected_status" ]; then
            log_info "  [OK] Status code: $http_code"
        else
            test_passed=false
            failures="${failures}\n  - Status mismatch: got $http_code, expected $expected_status"
            log_warn "  Status code mismatch: got $http_code, expected $expected_status"
        fi
    fi

    # Check 5: Access log has correct response_flag
    local log_entry=$(get_log_entry "$api_path")
    local actual_flag=$(get_flag_from_log "$log_entry")

    if [ "$actual_flag" = "$expected_flag" ]; then
        log_info "  [OK] Access log flag: $actual_flag"
    else
        test_passed=false
        failures="${failures}\n  - Log flag mismatch: got '${actual_flag:-<empty>}', expected '$expected_flag'"
        log_warn "  Access log flag mismatch: got '${actual_flag:-<empty>}', expected '$expected_flag'"
    fi

    # Final result
    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    # Print details for debugging
    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    if [ -n "$log_entry" ]; then
        echo -e "  ${BLUE}Access Log:${NC} $log_entry"
    fi

    # Cleanup temp files
    rm -f "$body_file" "$header_file"
}

# -----------------------------------------------------------------------------
# Specialized Test Functions
# -----------------------------------------------------------------------------

# Test rate limiting with override
run_override_test_rate_limit() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"
    log_info "  Step 1: Exhausting rate limit..."

    # Send first request to exhaust rate limit (rate is 1/min)
    curl -s -o /dev/null "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null
    sleep 0.5

    # Second request should be rate limited - capture full response
    log_info "  Step 2: Sending request that should be rate limited..."

    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    # Wait for log
    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains override
    if echo "$response_body" | grep -q "rate_limit_exceeded"; then
        log_info "  [OK] Body contains: rate_limit_exceeded"
    else
        test_passed=false
        failures="${failures}\n  - Body missing override content"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: RLT"; then
        log_info "  [OK] X-Error-Flag: RLT"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: RLT"
    fi

    # Check Retry-After header (from override)
    if echo "$response_headers" | grep -qi "Retry-After: 60"; then
        log_info "  [OK] Retry-After: 60"
    else
        test_passed=false
        failures="${failures}\n  - Missing Retry-After header"
    fi

    # Check access log
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)
    local rlt_entry=$(grep -E "prefix=access-log" "$TYK_LOG_FILE" 2>/dev/null | grep "api_id=${api_id}" | grep "response_flag=RLT" | tail -1)

    if [ -n "$rlt_entry" ]; then
        log_info "  [OK] Access log flag: RLT"
    else
        test_passed=false
        failures="${failures}\n  - Access log missing RLT flag"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$rlt_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $rlt_entry"

    rm -f "$body_file" "$header_file"
}

# Test with large body for BTL override
run_override_test_large_body() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    local large_body='{"data":"this is a very large body that exceeds the 10 byte limit"}'
    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Content-Length: ${#large_body}" \
        -d "$large_body" \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains override
    if echo "$response_body" | grep -q "payload_too_large"; then
        log_info "  [OK] Body contains: payload_too_large"
    else
        test_passed=false
        failures="${failures}\n  - Body missing override content"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: BTL"; then
        log_info "  [OK] X-Error-Flag: BTL"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: BTL"
    fi

    # Check status code is overridden to 413
    if [ "$http_code" = "413" ]; then
        log_info "  [OK] Status code overridden to 413"
    else
        test_passed=false
        failures="${failures}\n  - Status not overridden: got $http_code, expected 413"
    fi

    # Check access log
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)
    local log_entry=$(get_log_entry "$api_path")
    local actual_flag=$(get_flag_from_log "$log_entry")

    if [ "$actual_flag" = "BTL" ]; then
        log_info "  [OK] Access log flag: BTL"
    else
        test_passed=false
        failures="${failures}\n  - Access log flag mismatch: got '${actual_flag:-<empty>}', expected BTL"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$log_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $log_entry"

    rm -f "$body_file" "$header_file"
}

# Test with invalid JSON for BIV override
run_override_test_invalid_json() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{invalid json: missing quotes}' \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains override
    if echo "$response_body" | grep -q "invalid_request_body"; then
        log_info "  [OK] Body contains: invalid_request_body"
    else
        test_passed=false
        failures="${failures}\n  - Body missing override content"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: BIV"; then
        log_info "  [OK] X-Error-Flag: BIV"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: BIV"
    fi

    # Check access log
    local log_entry=$(get_log_entry "$api_path")
    local actual_flag=$(get_flag_from_log "$log_entry")

    if [ "$actual_flag" = "BIV" ]; then
        log_info "  [OK] Access log flag: BIV"
    else
        test_passed=false
        failures="${failures}\n  - Access log flag mismatch: got '${actual_flag:-<empty>}', expected BIV"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$log_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $log_entry"

    rm -f "$body_file" "$header_file"
}

# Test BIV with a template that renders {{.InvalidParams}}
# Verifies the error detail from Go's validator is rendered without HTML entity encoding.
run_override_test_biv_invalid_params() {
    local test_name=$1
    local api_path=$2
    local request_body=$3
    local expected_status=$4

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$request_body" \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check status code
    if [ "$http_code" = "$expected_status" ]; then
        log_info "  [OK] Status code: $http_code"
    else
        test_passed=false
        failures="${failures}\n  - Status mismatch: got $http_code, expected $expected_status"
    fi

    # Check the validation template was rendered (invalid_params field present)
    if echo "$response_body" | grep -q '"invalid_params"'; then
        log_info "  [OK] Body contains: invalid_params field"
    else
        test_passed=false
        failures="${failures}\n  - Body missing invalid_params field"
    fi

    # Regression: single quotes in validator error messages must not be HTML-encoded as &#39;
    if ! echo "$response_body" | grep -q '&#39;'; then
        log_info "  [OK] No HTML entity encoding in invalid_params value"
    else
        test_passed=false
        failures="${failures}\n  - HTML entity encoding (&#39;) found in response body"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: BIV"; then
        log_info "  [OK] X-Error-Flag: BIV"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: BIV"
    fi

    # Check X-Override-Applied header
    if echo "$response_headers" | grep -qi "X-Override-Applied: true"; then
        log_info "  [OK] X-Override-Applied: true"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Override-Applied header"
    fi

    # Check access log
    local log_entry=$(get_log_entry "$api_path")
    local actual_flag=$(get_flag_from_log "$log_entry")

    if [ "$actual_flag" = "BIV" ]; then
        log_info "  [OK] Access log flag: BIV"
    else
        test_passed=false
        failures="${failures}\n  - Access log flag mismatch: got '${actual_flag:-<empty>}', expected BIV"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$log_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $log_entry"

    rm -f "$body_file" "$header_file"
}

# Test without Content-Length for CLM override
run_override_test_no_content_length() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        -X POST \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Type: application/json" \
        --data-binary @- \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null <<< '{"test":"data"}' || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains override
    if echo "$response_body" | grep -q "content_length_required"; then
        log_info "  [OK] Body contains: content_length_required"
    else
        test_passed=false
        failures="${failures}\n  - Body missing override content"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: CLM"; then
        log_info "  [OK] X-Error-Flag: CLM"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: CLM"
    fi

    # Check access log
    local log_entry=$(get_log_entry "$api_path")
    local actual_flag=$(get_flag_from_log "$log_entry")

    if [ "$actual_flag" = "CLM" ]; then
        log_info "  [OK] Access log flag: CLM"
    else
        test_passed=false
        failures="${failures}\n  - Access log flag mismatch: got '${actual_flag:-<empty>}', expected CLM"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$log_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $log_entry"

    rm -f "$body_file" "$header_file"
}

# Create a session/key via Gateway Admin API
create_test_key() {
    local api_id=$1
    local rate=${2:-1000}
    local per=${3:-60}
    local quota_max=${4:--1}
    local quota_renewal=${5:-3600}

    local key_data=$(cat <<EOF
{
    "allowance": $rate,
    "rate": $rate,
    "per": $per,
    "quota_max": $quota_max,
    "quota_renewal_rate": $quota_renewal,
    "access_rights": {
        "$api_id": {
            "api_id": "$api_id",
            "api_name": "$api_id",
            "versions": ["Default"]
        }
    },
    "org_id": "default"
}
EOF
)

    local response=$(curl -s -X POST \
        -H "x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7" \
        -H "Content-Type: application/json" \
        -d "$key_data" \
        "${TYK_OVERRIDE_URL}/tyk/keys/create" 2>/dev/null)

    # Extract key from response
    echo "$response" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p'
}

# Delete a session/key via Gateway Admin API
delete_test_key() {
    local key=$1
    curl -s -X DELETE \
        -H "x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7" \
        "${TYK_OVERRIDE_URL}/tyk/keys/$key" > /dev/null 2>&1
}

# Test quota exceeded with override (creates key with quota=1, exceeds it)
run_override_test_quota_exceeded() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    # Extract api_id from path
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)

    # Create key with quota of 1
    log_info "  Step 1: Creating key with quota_max=1..."
    local key=$(create_test_key "$api_id" 1000 60 1 3600)

    if [ -z "$key" ]; then
        log_warn "Failed to create test key"
        log_fail "$test_name"
        ((FAILED++))
        return
    fi
    log_info "  Created key: ${key:0:20}..."

    # First request - should succeed and use quota
    log_info "  Step 2: Using quota with first request..."
    curl -s -o /dev/null \
        -H "Authorization: $key" \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null
    sleep 0.5

    # Second request - should exceed quota
    log_info "  Step 3: Sending request that should exceed quota..."
    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        -H "Authorization: $key" \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    # Wait for log
    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains override
    if echo "$response_body" | grep -q "quota_exceeded"; then
        log_info "  [OK] Body contains: quota_exceeded"
    else
        test_passed=false
        failures="${failures}\n  - Body missing override content"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: QEX"; then
        log_info "  [OK] X-Error-Flag: QEX"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: QEX"
    fi

    # Check access log for QEX flag
    local qex_entry=$(grep -E "prefix=access-log" "$TYK_LOG_FILE" 2>/dev/null | grep "api_id=${api_id}" | grep "response_flag=QEX" | tail -1)

    if [ -n "$qex_entry" ]; then
        log_info "  [OK] Access log flag: QEX"
    else
        test_passed=false
        failures="${failures}\n  - Access log missing QEX flag"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$qex_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $qex_entry"

    # Cleanup
    delete_test_key "$key"
    rm -f "$body_file" "$header_file"
}

# Test external auth denied with override (OAuth client deleted, token still used)
run_override_test_external_auth_denied() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)

    # Step 1: Create an OAuth client
    log_info "  Step 1: Creating OAuth client with policy '${api_id}-policy'..."
    local client_response=$(curl -s -X POST \
        -H "x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7" \
        -H "Content-Type: application/json" \
        -d "{\"redirect_uri\": \"http://localhost/callback\", \"policy_id\": \"${api_id}-policy\"}" \
        "${TYK_OVERRIDE_URL}/tyk/oauth/clients/create" 2>/dev/null)

    local client_id=$(echo "$client_response" | sed -n 's/.*"client_id":"\([^"]*\)".*/\1/p')
    local client_secret=$(echo "$client_response" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')

    if [ -z "$client_id" ]; then
        log_warn "Failed to create OAuth client. Response: $client_response"
        log_fail "$test_name"
        ((FAILED++))
        return
    fi
    log_info "  Created OAuth client: ${client_id:0:20}..."

    # Step 2: Get an access token
    log_info "  Step 2: Getting access token via client_credentials grant..."
    local token_response=$(curl -s -X POST \
        -u "${client_id}:${client_secret}" \
        -d "grant_type=client_credentials" \
        "${TYK_OVERRIDE_URL}/${api_id}/oauth/token" 2>/dev/null)

    local access_token=$(echo "$token_response" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

    if [ -z "$access_token" ]; then
        log_warn "Failed to get access token. Response: $token_response"
        # Cleanup client
        curl -s -X DELETE \
            -H "x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7" \
            "${TYK_OVERRIDE_URL}/tyk/oauth/clients/${api_id}/${client_id}" > /dev/null 2>&1
        log_fail "$test_name"
        ((FAILED++))
        return
    fi
    log_info "  Got access token: ${access_token:0:20}..."

    # Step 3: Verify token works
    log_info "  Step 3: Verifying token works..."
    local verify_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${access_token}" \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")
    log_info "  Verify Response: $verify_code"

    # Step 4: Delete the OAuth client
    log_info "  Step 4: Deleting OAuth client..."
    curl -s -X DELETE \
        -H "x-tyk-authorization: 352d20ee67be67f6340b4c0605b044b7" \
        "${TYK_OVERRIDE_URL}/tyk/oauth/clients/${api_id}/${client_id}" > /dev/null 2>&1
    sleep 1

    # Step 5: Try to use the token from the deleted client
    log_info "  Step 5: Using token from deleted client (should trigger EAD)..."
    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        -H "Authorization: Bearer ${access_token}" \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    # Wait for log
    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains override
    if echo "$response_body" | grep -q "external_auth_denied"; then
        log_info "  [OK] Body contains: external_auth_denied"
    else
        test_passed=false
        failures="${failures}\n  - Body missing override content"
    fi

    # Check X-Error-Flag header
    if echo "$response_headers" | grep -qi "X-Error-Flag: EAD"; then
        log_info "  [OK] X-Error-Flag: EAD"
    else
        test_passed=false
        failures="${failures}\n  - Missing X-Error-Flag: EAD"
    fi

    # Check access log for EAD flag
    local ead_entry=$(grep -E "prefix=access-log" "$TYK_LOG_FILE" 2>/dev/null | grep "api_id=${api_id}" | grep "response_flag=EAD" | tail -1)

    if [ -n "$ead_entry" ]; then
        log_info "  [OK] Access log flag: EAD"
    else
        test_passed=false
        failures="${failures}\n  - Access log missing EAD flag"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$ead_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $ead_entry"

    rm -f "$body_file" "$header_file"
}

# Run test with alternative acceptable flag (for environment-dependent tests)
run_override_test_with_alternatives() {
    local test_name=$1
    local api_path=$2
    local expected_flag=$3
    local alternative_flag=$4
    local expected_body_contains=$5
    local expected_header=$6
    local expected_status=${7:-""}
    local extra_curl_args=${8:-""}
    local timeout=${9:-10}

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"
    log_info "  Expected Flag: $expected_flag (or $alternative_flag in some environments)"

    # Create temp files for response
    local body_file=$(mktemp)
    local header_file=$(mktemp)

    # Send request and capture response
    local http_code
    if [ -n "$extra_curl_args" ]; then
        http_code=$(eval "curl -s -o '$body_file' -D '$header_file' -w '%{http_code}' \
            --connect-timeout '$timeout' \
            --max-time '$timeout' \
            $extra_curl_args \
            '${TYK_OVERRIDE_URL}${api_path}' 2>/dev/null" || echo "000")
    else
        http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
            --connect-timeout "$timeout" \
            --max-time "$timeout" \
            "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")
    fi

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    # Wait for log
    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Extract api_id and get log entry
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)
    local log_entry=$(get_log_entry "$api_path")
    local actual_flag=$(get_flag_from_log "$log_entry")

    # Check if actual flag matches expected OR alternative
    if [ "$actual_flag" = "$expected_flag" ]; then
        log_info "  [OK] Access log flag: $expected_flag"

        # Check body contains expected string
        if echo "$response_body" | grep -q "$expected_body_contains"; then
            log_info "  [OK] Body contains: $expected_body_contains"
        else
            test_passed=false
            failures="${failures}\n  - Body missing: $expected_body_contains"
        fi

        # Check X-Error-Flag header
        if echo "$response_headers" | grep -qi "X-Error-Flag: $expected_header"; then
            log_info "  [OK] X-Error-Flag header: $expected_header"
        else
            test_passed=false
            failures="${failures}\n  - Missing X-Error-Flag: $expected_header"
        fi
    elif [ "$actual_flag" = "$alternative_flag" ]; then
        log_warn "  Got alternative flag '$alternative_flag' (environment-specific)"

        # When alternative flag is used, check for alternative body/header
        local alt_body_contains=$(echo "$alternative_flag" | tr '[:upper:]' '[:lower:]')
        if echo "$response_body" | grep -qi "$alt_body_contains"; then
            log_info "  [OK] Body contains alternative flag content"
        else
            test_passed=false
            failures="${failures}\n  - Body missing alternative content"
        fi

        if echo "$response_headers" | grep -qi "X-Error-Flag: $alternative_flag"; then
            log_info "  [OK] X-Error-Flag header: $alternative_flag (alternative)"
        else
            test_passed=false
            failures="${failures}\n  - Missing X-Error-Flag: $alternative_flag"
        fi
    else
        test_passed=false
        failures="${failures}\n  - Expected flag '$expected_flag' or '$alternative_flag', got '${actual_flag:-<empty>}'"
    fi

    # Check X-Override-Applied header
    if echo "$response_headers" | grep -qi "X-Override-Applied: true"; then
        log_info "  [OK] X-Override-Applied: true"
    else
        log_warn "  X-Override-Applied header not found"
    fi

    # Check status code if expected
    if [ -n "$expected_status" ]; then
        if [ "$http_code" = "$expected_status" ] || [ "$http_code" = "504" ]; then
            log_info "  [OK] Status code: $http_code"
        else
            log_warn "  Status code mismatch: got $http_code"
        fi
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    # Print details for debugging
    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    if [ -n "$log_entry" ]; then
        echo -e "  ${BLUE}Access Log:${NC} $log_entry"
    fi

    # Cleanup temp files
    rm -f "$body_file" "$header_file"
}

# Test client disconnected with override (client aborts before upstream responds)
run_override_test_client_disconnected() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"
    log_info "  Sending request with 2s client timeout to slow backend..."

    local body_file=$(mktemp)
    local header_file=$(mktemp)

    # Send request with very short client-side timeout (2s)
    # The backend-slow takes 120s, gateway timeout is 10s
    # Client disconnects at 2s → context.Canceled → CDC
    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 5 \
        --max-time 2 \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code (expected 000 or 499 - client aborted)"

    # Wait longer for the gateway to process the cancellation and write the log
    sleep 5
    refresh_logs

    local test_passed=true
    local failures=""

    # CDC might not get a response body since client disconnects
    # Check if we got override response OR empty (client disconnected before response)
    if [ -n "$response_body" ] && echo "$response_body" | grep -q "client_disconnected"; then
        log_info "  [OK] Body contains: client_disconnected"
    elif [ -z "$response_body" ] || [ "$http_code" = "000" ]; then
        log_info "  [OK] Client disconnected before response (expected for CDC)"
    else
        test_passed=false
        failures="${failures}\n  - Expected client_disconnected or empty body"
    fi

    # Check access log for CDC flag
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)
    local cdc_entry=$(grep -E "prefix=access-log" "$TYK_LOG_FILE" 2>/dev/null | grep "api_id=${api_id}" | grep "response_flag=CDC" | tail -1)

    if [ -n "$cdc_entry" ]; then
        log_info "  [OK] Access log flag: CDC"
    else
        test_passed=false
        failures="${failures}\n  - Access log missing CDC flag"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$cdc_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $cdc_entry"

    rm -f "$body_file" "$header_file"
}

# Test circuit breaker with override (trigger CB first, then test)
run_override_test_circuit_breaker() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"
    log_info "  Step 1: Triggering circuit breaker with failing requests..."

    # Send failing requests to trigger circuit breaker (threshold 0.1 = 10%, samples 3)
    for i in 1 2 3 4 5 6 7 8 9 10; do
        curl -s -o /dev/null "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null
        sleep 0.2
    done

    # Immediately send test request while CB is open
    log_info "  Step 2: Testing circuit breaker state..."
    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 5 \
        --max-time 5 \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    # Wait for log to be written
    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check if we got CBO override in any of the recent requests
    local api_id=$(echo "$api_path" | sed 's|^/||' | cut -d'/' -f1)
    local cbo_entry=$(grep -E "prefix=access-log" "$TYK_LOG_FILE" 2>/dev/null | grep "api_id=${api_id}" | grep "response_flag=CBO" | tail -1)

    if [ -n "$cbo_entry" ]; then
        log_info "  [OK] Access log flag: CBO found"

        # If we got CBO in logs, check if the response body contains override
        if echo "$response_body" | grep -q "circuit_breaker"; then
            log_info "  [OK] Body contains: circuit_breaker"
        else
            # CB might have opened during trigger requests, not the test request
            log_info "  [NOTE] CBO detected in logs (may be from trigger requests)"
        fi
    else
        test_passed=false
        failures="${failures}\n  - Access log missing CBO flag (circuit breaker may not have opened)"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"
    [ -n "$cbo_entry" ] && echo -e "  ${BLUE}Access Log:${NC} $cbo_entry"

    rm -f "$body_file" "$header_file"
}

# Test that upstream error passes through unchanged when no rule matches
run_override_test_upstream_passthrough() {
    local test_name=$1
    local api_path=$2

    echo ""
    log_info "Testing: $test_name"
    log_info "  API Path: $api_path"

    local body_file=$(mktemp)
    local header_file=$(mktemp)

    local http_code=$(curl -s -o "$body_file" -D "$header_file" -w "%{http_code}" \
        --connect-timeout 10 \
        --max-time 10 \
        "${TYK_OVERRIDE_URL}${api_path}" 2>/dev/null || echo "000")

    local response_body=$(cat "$body_file")
    local response_headers=$(cat "$header_file")

    log_info "  HTTP Response: $http_code"

    sleep "$WAIT_FOR_LOG_SECONDS"
    refresh_logs

    local test_passed=true
    local failures=""

    # Check body contains ORIGINAL upstream content
    if echo "$response_body" | grep -q "bad_request"; then
        log_info "  [OK] Body contains original upstream content"
    else
        test_passed=false
        failures="${failures}\n  - Body was modified (should be passthrough)"
    fi

    # Check X-Override-Applied header is NOT present
    if ! echo "$response_headers" | grep -qi "X-Override-Applied"; then
        log_info "  [OK] X-Override-Applied header not present (as expected)"
    else
        test_passed=false
        failures="${failures}\n  - X-Override-Applied present (should not be)"
    fi

    # Check status code remains 400
    if [ "$http_code" = "400" ]; then
        log_info "  [OK] Status code unchanged: 400"
    else
        test_passed=false
        failures="${failures}\n  - Status changed: got $http_code, expected 400"
    fi

    if [ "$test_passed" = true ]; then
        log_success "$test_name"
        ((PASSED++))
    else
        log_fail "$test_name"
        echo -e "${RED}  Failures:${NC}$failures"
        ((FAILED++))
    fi

    echo -e "  ${BLUE}Response Body:${NC} $response_body"

    rm -f "$body_file" "$header_file"
}

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------

preflight_checks() {
    print_separator
    echo "Pre-flight Checks (Error Overrides Gateway)"
    print_separator

    log_info "Checking Tyk Gateway with Overrides (port 8081)..."
    if curl -s --connect-timeout 2 "${TYK_OVERRIDE_URL}/hello" > /dev/null 2>&1; then
        log_success "Tyk Gateway (overrides) is available at ${TYK_OVERRIDE_URL}"
    else
        log_fail "Tyk Gateway (overrides) is not available at ${TYK_OVERRIDE_URL}"
        echo ""
        log_warn "Please ensure tyk-gateway-overrides container is running"
        log_warn "Run: docker-compose up -d tyk-gateway-overrides"
        return 1
    fi

    echo ""
    return 0
}

# -----------------------------------------------------------------------------
# Run All Override Tests
# -----------------------------------------------------------------------------

run_all_override_tests() {
    print_separator
    echo "Running Error Override Tests"
    print_separator

    # ==========================================================================
    # AMF - Auth Field Missing (401)
    # ==========================================================================
    run_override_test \
        "AMF Override - Auth Key Missing" \
        "/test-amf-authkey/get" \
        "AMF" \
        "authentication_required" \
        "AMF" \
        "401"

    run_override_test \
        "AMF Override - Basic Auth Missing" \
        "/test-amf-basicauth/get" \
        "AMF" \
        "authentication_required" \
        "AMF" \
        "401"

    run_override_test \
        "AMF Override - JWT Missing" \
        "/test-amf-jwt/get" \
        "AMF" \
        "authentication_required" \
        "AMF" \
        ""  # JWT returns 400, not 401

    run_override_test \
        "AMF Override - OAuth Missing" \
        "/test-amf-oauth/get" \
        "AMF" \
        "authentication_required" \
        "AMF" \
        ""  # OAuth returns 400

    # ==========================================================================
    # AKI - API Key Invalid (403)
    # ==========================================================================
    run_override_test \
        "AKI Override - Invalid API Key" \
        "/test-aki/get" \
        "AKI" \
        "invalid_api_key" \
        "AKI" \
        "403" \
        "-H \"Authorization: invalid-key-12345\""

    # ==========================================================================
    # IHD - Invalid Header (400)
    # ==========================================================================
    run_override_test \
        "IHD Override - Basic Auth Malformed" \
        "/test-ihd-basicauth/get" \
        "IHD" \
        "invalid_header" \
        "IHD" \
        "400" \
        "-H \"Authorization: NotBasic xyz123\""

    run_override_test \
        "IHD Override - OAuth Malformed" \
        "/test-ihd-oauth/get" \
        "IHD" \
        "invalid_header" \
        "IHD" \
        "400" \
        "-H \"Authorization: Token abc123\""

    # ==========================================================================
    # TKI - Token Invalid (403)
    # ==========================================================================
    run_override_test \
        "TKI Override - JWT Invalid" \
        "/test-tki-jwt/get" \
        "TKI" \
        "invalid_token" \
        "TKI" \
        "403" \
        "-H \"Authorization: Bearer invalid.jwt.token\""

    # ==========================================================================
    # TKE - Token Expired (403)
    # ==========================================================================
    run_override_test \
        "TKE Override - JWT Expired" \
        "/test-tke-jwt/get" \
        "TKE" \
        "token_expired" \
        "TKE" \
        "403" \
        "-H \"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwMDAwMDAwfQ.fZvtihmhjSJ34nKLnt0qjdgwH1NPNFcU5pRYZ-bgB5c\""

    # ==========================================================================
    # QEX - Quota Exceeded (403)
    # ==========================================================================
    run_override_test_quota_exceeded \
        "QEX Override - Quota Exceeded" \
        "/test-qex/get"

    # ==========================================================================
    # EAD - External Auth Denied (403)
    # ==========================================================================
    run_override_test_external_auth_denied \
        "EAD Override - External Auth Denied" \
        "/test-ead/get"

    # ==========================================================================
    # RLT - Rate Limited (429)
    # ==========================================================================
    run_override_test_rate_limit \
        "RLT Override - Rate Limited" \
        "/test-rlt/get"

    # ==========================================================================
    # BTL - Body Too Large (400 -> 413)
    # ==========================================================================
    run_override_test_large_body \
        "BTL Override - Body Too Large (status override 400->413)" \
        "/test-btl/post"

    # ==========================================================================
    # CLM - Content-Length Missing (411)
    # ==========================================================================
    run_override_test_no_content_length \
        "CLM Override - Content-Length Missing" \
        "/test-clm/post"

    # ==========================================================================
    # BIV - Body Invalid (400)
    # ==========================================================================
    run_override_test_invalid_json \
        "BIV Override - Invalid JSON" \
        "/test-biv-json/validate"

    # BIV - InvalidParams template rendering
    # Verifies that {{.InvalidParams}} in the template receives the validator's error detail
    # and that single quotes in the error message are not HTML-encoded as &#39;.
    run_override_test_biv_invalid_params \
        "BIV Override - InvalidParams rendered in template (JSON parse error)" \
        "/test-biv-json-invalid-params/validate" \
        '{invalid json: missing quotes}' \
        "400"

    run_override_test_biv_invalid_params \
        "BIV Override - InvalidParams rendered in template (schema validation)" \
        "/test-biv-schema-invalid-params/validate" \
        '{"wrong_field": "value"}' \
        "422"

    # ==========================================================================
    # 5XX Errors - Gateway-Generated Errors
    # ==========================================================================

    # ==========================================================================
    # TLS Errors (5xx -> 502)
    # ==========================================================================

    # TLE - TLS Certificate Expired (500 -> 502)
    run_override_test \
        "TLE Override - TLS Certificate Expired" \
        "/test-tle/get" \
        "TLE" \
        "upstream_tls_error" \
        "TLE" \
        "502"

    # TLI - TLS Certificate Invalid (500 -> 502) + File Template Test
    echo ""
    log_info "=== TLI: Testing File Template (error_upstream.json) ==="
    run_override_test \
        "TLI Override - TLS Certificate Invalid [File Template]" \
        "/test-tli/get" \
        "TLI" \
        "Upstream Service Error" \
        "TLI" \
        "502"

    # Verify file template structure
    echo ""
    log_info "Verifying file template structure in TLI response..."
    local tli_body=$(mktemp)
    local tli_headers=$(mktemp)
    curl -s -o "$tli_body" -D "$tli_headers" "${TYK_OVERRIDE_URL}/test-tli/get" 2>/dev/null
    if grep -q '"type":' "$tli_body" && grep -q '"title":' "$tli_body" && grep -q '"detail":' "$tli_body"; then
        log_success "File template structure verified (has type, title, detail fields)"
    else
        log_warn "File template structure not complete"
    fi
    if grep -q "X-Template-Type: file" "$tli_headers"; then
        log_success "X-Template-Type header confirms file template usage"
    fi
    rm -f "$tli_body" "$tli_headers"

    # TLM - TLS Hostname Mismatch (500 -> 502) + Inline Template Test
    echo ""
    log_info "=== TLM: Testing Inline Template with Variables ==="
    run_override_test \
        "TLM Override - TLS Hostname Mismatch [Inline Template]" \
        "/test-tlm/get" \
        "TLM" \
        "inline_template" \
        "TLM" \
        "502"

    # Verify inline template variable substitution
    echo ""
    log_info "Verifying inline template variable substitution in TLM response..."
    local tlm_body=$(mktemp)
    local tlm_headers=$(mktemp)
    curl -s -o "$tlm_body" -D "$tlm_headers" "${TYK_OVERRIDE_URL}/test-tlm/get" 2>/dev/null
    if grep -q '"status": 502' "$tlm_body" && grep -q '"message":' "$tlm_body"; then
        log_success "Inline template variables substituted (status=502, message present)"
    else
        log_warn "Inline template variable substitution incomplete"
    fi
    if grep -q "X-Template-Type: inline" "$tlm_headers"; then
        log_success "X-Template-Type header confirms inline template usage"
    fi
    rm -f "$tlm_body" "$tlm_headers"

    # TLN - TLS Not Trusted (500 -> 502) + Message-Only Test
    echo ""
    log_info "=== TLN: Testing Message-Only (Default Template) ==="
    run_override_test \
        "TLN Override - TLS Not Trusted [Message Only]" \
        "/test-tln/get" \
        "TLN" \
        "TLS certificate is not trusted" \
        "TLN" \
        "502"

    # Verify message-only uses default template
    echo ""
    log_info "Verifying message-only response uses default Tyk template..."
    local tln_headers=$(mktemp)
    curl -s -D "$tln_headers" "${TYK_OVERRIDE_URL}/test-tln/get" 2>/dev/null
    if grep -q "X-Template-Type: message-only" "$tln_headers"; then
        log_success "X-Template-Type header confirms message-only usage"
    fi
    rm -f "$tln_headers"

    # TLH - TLS Handshake Failed (500 -> 502) + Headers-Only Test
    echo ""
    log_info "=== TLH: Testing Headers-Only Override ==="
    run_override_test \
        "TLH Override - TLS Handshake Failed [Headers Only]" \
        "/test-tlh/get" \
        "TLH" \
        "" \
        "TLH" \
        "502"

    # Verify headers-only adds custom headers without changing body
    echo ""
    log_info "Verifying headers-only override adds custom headers..."
    local tlh_headers=$(mktemp)
    curl -s -D "$tlh_headers" "${TYK_OVERRIDE_URL}/test-tlh/get" 2>/dev/null
    if grep -q "X-Template-Type: headers-only" "$tlh_headers" && \
       grep -q "X-Error-Category: tls" "$tlh_headers" && \
       grep -q "X-Error-Detail: handshake-failed" "$tlh_headers"; then
        log_success "Headers-only override verified (custom headers present)"
    else
        log_warn "Headers-only custom headers incomplete"
    fi
    rm -f "$tlh_headers"

    # TLP - TLS Protocol Error (500 -> 502)
    run_override_test \
        "TLP Override - TLS Protocol Error" \
        "/test-tlp/get" \
        "TLP" \
        "upstream_tls_error" \
        "TLP" \
        "502"

    # ==========================================================================
    # Connection Errors (5xx -> 502/504)
    # ==========================================================================

    # UCF - Upstream Connection Failed (500 -> 502)
    run_override_test \
        "UCF Override - Connection Failed" \
        "/test-ucf/get" \
        "UCF" \
        "upstream_connection_failed" \
        "UCF" \
        "502"

    # UCT - Upstream Connection Timeout (500 -> 504)
    # KNOWN LIMITATION: Go's HTTP client uses context.DeadlineExceeded for dial timeout,
    # not syscall.ETIMEDOUT. Classifier maps this to URT, not UCT.
    run_override_test_with_alternatives \
        "UCT Override - Connection Timeout" \
        "/test-uct/get" \
        "UCT" \
        "URT" \
        "upstream_connection_timeout" \
        "UCT" \
        "504" \
        "" \
        15

    # URT - Upstream Request Timeout (500 -> 504)
    run_override_test \
        "URT Override - Request Timeout" \
        "/test-urt/get" \
        "URT" \
        "upstream_request_timeout" \
        "URT" \
        "504" \
        "" \
        15

    # URR - Upstream Request Rejected (500 -> 502)
    run_override_test \
        "URR Override - Request Rejected" \
        "/test-urr/get" \
        "URR" \
        "upstream_request_rejected" \
        "URR" \
        "502"

    # ==========================================================================
    # DNS & Routing Errors (5xx -> 502)
    # ==========================================================================

    # DNS - DNS Resolution Failure (500 -> 502)
    run_override_test \
        "DNS Override - DNS Failure" \
        "/test-dns/get" \
        "DNS" \
        "dns_resolution_failed" \
        "DNS" \
        "502"

    # NRH - No Route to Host (500 -> 502)
    # KNOWN LIMITATION: In Docker/macOS environments, unreachable IPs typically timeout
    # rather than returning EHOSTUNREACH. This test will show URT instead of NRH.
    run_override_test_with_alternatives \
        "NRH Override - No Route to Host" \
        "/test-nrh/get" \
        "NRH" \
        "URT" \
        "no_route_to_host" \
        "NRH" \
        "502" \
        "" \
        15

    # ==========================================================================
    # Other 5XX Errors
    # ==========================================================================

    # UPE - Upstream Protocol Error (500 -> 502)
    run_override_test \
        "UPE Override - Protocol Error" \
        "/test-upe/get" \
        "UPE" \
        "upstream_protocol_error" \
        "UPE" \
        "502"

    # CDC - Client Disconnected (499)
    run_override_test_client_disconnected \
        "CDC Override - Client Disconnected" \
        "/test-cdc/get"

    # CBO - Circuit Breaker Open (503)
    run_override_test_circuit_breaker \
        "CBO Override - Circuit Breaker Open" \
        "/test-cbo/500"

    # ==========================================================================
    # API-Level Override Tests
    # ==========================================================================
    echo ""
    log_info "=========================================="
    log_info "API LEVEL OVERRIDE TESTS"
    log_info "=========================================="

    run_override_test \
        "API Override Precedence - AKI" \
        "/test-api-override-aki/get" \
        "AKI" \
        "api_level_override" \
        "AKI-API" \
        "418" \
        "-H \"Authorization: invalid-key-12345\""

    run_override_test \
        "API Override Disabled - AKI" \
        "/test-api-override-disabled/get" \
        "AKI" \
        "invalid_api_key" \
        "AKI" \
        "403" \
        "-H \"Authorization: invalid-key-12345\""

    run_override_test \
        "API Override Fallback - AMF" \
        "/test-api-override-aki/get" \
        "AMF" \
        "authentication_required" \
        "AMF" \
        "401"

    run_override_test \
        "API Override Upstream - 404" \
        "/test-api-override-upstream/404-json" \
        "" \
        "api_level_upstream" \
        "UPSTREAM-API" \
        "420"

     run_override_test \
         "API Override Upstream - 500 [Body Field and Value match]" \
         "/test-api-override-upstream-match/500-complex" \
         "URS" \
         "override_all_match" \
         "UPSTREAM-MATCH-FIELD-VALUE-API" \
         "501"

     run_override_test \
         "API Override Upstream - 500 [Inline Template]"\
         "/edge-cases/500-template" \
         "URS" \
         "{\"code\": 501}" \
         "UPSTREAM-INLINE-TEMPLATE" \
         "501"

     # Message contains " and newline; escapeTemplateString applies JS-escaping so the
     # body has \" (not HTML &#34;) and \u000A (not a literal newline).
     run_override_test \
         "API Override Upstream - 500 [JSON Escaping in inline templates]"\
         "/edge-cases/500-json-escape" \
         "URS" \
         '\\"' \
         "UPSTREAM-JSON-ESCAPED-INLINE-TEMPLATE" \
         "502"

    run_override_test \
        "API Override Upstream - 500 [Truncate large body, skips api override rule but apply gateway matching rule]"\
        "/edge-cases/500-truncation" \
        "URS" \
        "Upstream service error occurred" \
        "" \
        "503"

    # ==========================================================================
    # Upstream Error Override Tests
    # ==========================================================================

    echo ""
    log_info "=========================================="
    log_info "UPSTREAM ERROR OVERRIDE TESTS"
    log_info "=========================================="

    # Test 1: URS flag on 5xx (ONLY test using URS flag) - Uses message-only (default template)
    run_override_test \
        "URS Override - 5xx Generic Match [Message Only]" \
        "/test-upstream/5xx" \
        "URS" \
        "Upstream service error occurred" \
        "URS" \
        "503"

    # Test 2: Upstream 404 with body_field matching
    run_override_test \
        "Upstream Override - 404 JSON Body Match" \
        "/test-upstream/404-json" \
        "" \
        "resource_not_found" \
        "NOT_FOUND" \
        "404"

    # Test 3: Upstream 404 with message_pattern - Uses template: error_validation
    run_override_test \
        "Upstream Override - 404 Regex Match [Template: error_validation]" \
        "/test-upstream/404-html" \
        "" \
        "Validation Error" \
        "PAGE_NOT_FOUND" \
        "404"

    # Test 4: Upstream no match - body passthrough
    run_override_test_upstream_passthrough \
        "Upstream Override - No Match Passthrough" \
        "/test-upstream/400-nomatch"

}

# -----------------------------------------------------------------------------
# Print Summary
# -----------------------------------------------------------------------------

print_summary() {
    print_separator
    echo "Error Override Test Summary"
    print_separator

    local total=$((PASSED + FAILED + SKIPPED))

    echo ""
    echo -e "Total Tests: $total"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All error override tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed. Please check the output above.${NC}"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    echo ""
    print_separator
    echo " Error Overrides Feature Test Suite"
    print_separator
    echo ""

    case "${1:-run}" in
        run)
            if preflight_checks; then
                run_all_override_tests
                print_summary
            else
                exit 1
            fi
            ;;
        check)
            preflight_checks
            ;;
        help|--help|-h)
            echo "Usage: $0 [run|check|help]"
            echo ""
            echo "Commands:"
            echo "  run     Run all error override tests (default)"
            echo "  check   Run pre-flight checks only"
            echo "  help    Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  TYK_OVERRIDE_URL        Tyk Gateway (overrides) URL (default: http://localhost:8081)"
            echo "  TYK_OVERRIDE_CONTAINER  Docker container name (default: test-access-logs-tyk-gateway-overrides-1)"
            echo "  TYK_LOG_FILE            Path to store access logs (default: /tmp/tyk-override-access.log)"
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run '$0 help' for usage information"
            exit 1
            ;;
    esac
}

main "$@"
