#!/bin/bash

# Demonstrates nonce desynchronization issues without auto-recovery
# This script shows the problems that occur when dashboard restarts invalidate nonces

set -e

# Configuration
DASHBOARD_DIR="../tyk-analytics"
GATEWAY_DIR="."
DASHBOARD_PORT=3000
GATEWAY_PORT=8282
TEST_API_ENDPOINT="http://localhost:${GATEWAY_PORT}/hello"
DASHBOARD_CONFIG="../tyk-develop-env/confs/tyk_analytics.conf"
GATEWAY_CONFIG="../tyk-develop-env/confs/tyk_pro.conf"
POLICIES_ENDPOINT="http://localhost:${GATEWAY_PORT}/tyk/policies"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Global variables
DASHBOARD_PID=""
GATEWAY_PID=""

# Cleanup function
cleanup() {
    log "Cleaning up processes..."
    
    if [[ -n "$DASHBOARD_PID" ]]; then
        kill $DASHBOARD_PID 2>/dev/null || true
        wait $DASHBOARD_PID 2>/dev/null || true
    fi
    
    if [[ -n "$GATEWAY_PID" ]]; then
        kill $GATEWAY_PID 2>/dev/null || true
        wait $GATEWAY_PID 2>/dev/null || true
    fi
    
    # Clean up log files
    rm -f dashboard.log gateway.log
    
    success "Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Start dashboard
start_dashboard() {
    log "Starting dashboard on port $DASHBOARD_PORT..."
    cd "$DASHBOARD_DIR"
    
    TYK_DB_LISTENPORT=$DASHBOARD_PORT \
    TYK_DB_STREAMING_ALLOWALL=true \
    TYK_DB_STREAMING_ENABLED=true \
    ./tyk-analytics --conf "$DASHBOARD_CONFIG" > ../tyk/dashboard.log 2>&1 &
    
    DASHBOARD_PID=$!
    cd - >/dev/null
    
    # Wait for dashboard to start
    for i in {1..30}; do
        if curl -s "http://localhost:${DASHBOARD_PORT}/admin/dashboard_stats" >/dev/null 2>&1; then
            success "Dashboard started (PID: $DASHBOARD_PID)"
            return 0
        fi
        sleep 1
    done
    
    error "Dashboard failed to start"
    exit 1
}

# Start gateway
start_gateway() {
    log "Starting gateway on port $GATEWAY_PORT..."
    cd "$GATEWAY_DIR"
    
    TYK_LOGLEVEL=debug \
    TYK_GW_LISTENPORT=$GATEWAY_PORT \
    TYK_GW_HTTPPROFILE=true \
    TYK_GW_STREAMING_ENABLED=true \
    ./tyk --conf="$GATEWAY_CONFIG" --httpprofile > gateway.log 2>&1 &
    
    GATEWAY_PID=$!
    cd - >/dev/null
    
    # Wait for gateway to start
    for i in {1..30}; do
        if curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1; then
            success "Gateway started (PID: $GATEWAY_PID)"
            return 0
        fi
        sleep 1
    done
    
    error "Gateway failed to start"
    exit 1
}

# Trigger policy loading manually
trigger_policy_loading() {
    log "Triggering policy loading manually..."
    # Try to force policy refresh by calling the policies endpoint
    curl -s -H "X-Tyk-Authorization: 352d20ee67be67f6340b4c0605b044b7" \
         "http://localhost:${GATEWAY_PORT}/tyk/reload?block=true" >/dev/null 2>&1 || true
    
    # Also try hitting the policies endpoint
    curl -s -H "X-Tyk-Authorization: 352d20ee67be67f6340b4c0605b044b7" \
         "$POLICIES_ENDPOINT" >/dev/null 2>&1 || true
}

# Main test
main() {
    log "Starting nonce desynchronization demonstration (without auto-recovery)"
    log "====================================================================="
    
    start_dashboard
    start_gateway
    
    # Let services stabilize
    log "Allowing services to stabilize..."
    sleep 5
    
    # Initial policy loading
    log "Triggering initial policy loading..."
    trigger_policy_loading
    sleep 2
    
    log "=== INITIAL STATE - Gateway logs ==="
    tail -20 gateway.log | grep -E "(policy|nonce|dashboard|error)" || echo "No relevant logs"
    
    # Kill dashboard to invalidate nonces
    log "Killing dashboard to invalidate nonces..."
    kill $DASHBOARD_PID 2>/dev/null || true
    wait $DASHBOARD_PID 2>/dev/null || true
    DASHBOARD_PID=""
    
    sleep 2
    
    # Restart dashboard (this invalidates all nonces)
    log "Restarting dashboard (this invalidates all existing nonces)..."
    start_dashboard
    
    sleep 3
    
    # Now try to trigger policy loading - this should fail with nonce issues
    log "Attempting to trigger policy loading with invalid nonces..."
    for i in {1..5}; do
        log "Attempt $i: Triggering policy reload..."
        trigger_policy_loading
        sleep 2
    done
    
    log "=== AFTER DASHBOARD RESTART - Gateway logs ==="
    tail -30 gateway.log | grep -E "(policy|nonce|dashboard|error|failed)" || echo "No relevant error logs"
    
    log "=== FULL ERROR ANALYSIS ==="
    if grep -q "Nonce failed\|nonce.*failed\|No node ID Found" gateway.log; then
        error "❌ NONCE FAILURES DETECTED (as expected without auto-recovery):"
        grep -E "Nonce failed|nonce.*failed|No node ID Found" gateway.log
    else
        warning "⚠️ No clear nonce failures detected - may need different approach"
    fi
    
    if grep -q "Policy request.*failure\|Policy request.*failed" gateway.log; then
        error "❌ POLICY REQUEST FAILURES DETECTED (as expected without auto-recovery):"
        grep -E "Policy request.*failure|Policy request.*failed" gateway.log
    else
        warning "⚠️ No clear policy request failures detected"
    fi
    
    log "Test completed - this demonstrates the issues that auto-recovery fixes"
}

# Run main function
main "$@"