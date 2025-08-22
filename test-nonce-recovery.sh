#!/bin/bash

# Dashboard Restart Test Script - Tests nonce desynchronization recovery
# This script tests the auto-recovery mechanism when dashboard restarts invalidate nonces

set -e

# Configuration
DASHBOARD_DIR="../tyk-analytics"
GATEWAY_DIR="."
DASHBOARD_PORT=3000
GATEWAY_PORT=8282
TEST_API_ENDPOINT="http://localhost:${GATEWAY_PORT}/hello"
DASHBOARD_CONFIG="../tyk-develop-env/confs/tyk_analytics.conf"
GATEWAY_CONFIG="../tyk-develop-env/confs/tyk_pro.conf"

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

# Cleanup function
cleanup() {
    log "Cleaning up processes..."
    
    # Kill dashboard if running
    if [[ -n "$DASHBOARD_PID" ]]; then
        kill $DASHBOARD_PID 2>/dev/null || true
        wait $DASHBOARD_PID 2>/dev/null || true
    fi
    
    # Kill gateway if running
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

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if [[ ! -d "$DASHBOARD_DIR" ]]; then
        error "Dashboard directory not found: $DASHBOARD_DIR"
        exit 1
    fi
    
    if [[ ! -f "$DASHBOARD_CONFIG" ]]; then
        error "Dashboard config not found: $DASHBOARD_CONFIG"
        exit 1
    fi
    
    if [[ ! -f "$GATEWAY_CONFIG" ]]; then
        error "Gateway config not found: $GATEWAY_CONFIG"
        exit 1
    fi
    
    # Check if Redis is running
    if ! redis-cli ping >/dev/null 2>&1; then
        error "Redis is not running. Please start Redis first."
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Build dashboard
build_dashboard() {
    log "Building dashboard..."
    cd "$DASHBOARD_DIR"
    go build -o tyk-analytics || {
        error "Failed to build dashboard"
        exit 1
    }
    cd - >/dev/null
    success "Dashboard built successfully"
}

# Build gateway
build_gateway() {
    log "Building gateway..."
    cd "$GATEWAY_DIR"
    go build --tags ee -o tyk || {
        error "Failed to build gateway"
        exit 1
    }
    cd - >/dev/null
    success "Gateway built successfully"
}

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
    log "Waiting for dashboard to initialize..."
    for i in {1..30}; do
        if curl -s "http://localhost:${DASHBOARD_PORT}/admin/dashboard_stats" >/dev/null 2>&1; then
            success "Dashboard started successfully (PID: $DASHBOARD_PID)"
            return 0
        fi
        sleep 1
    done
    
    error "Dashboard failed to start within 30 seconds"
    cat dashboard.log
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
    TYK_GW_STREAMING_ENABLEWEBSOCKETDETAILEDRECORDING=true \
    TYK_GW_STREAMING_ENABLEWEBSOCKETRATELIMITING=true \
    TYK_GW_STREAMING_ENABLEWEBSOCKETCLOSEONRATELIMIT=true \
    TYK_GW_STREAMING_ALLOWALL=true \
    ./tyk --conf="$GATEWAY_CONFIG" --httpprofile > gateway.log 2>&1 &
    
    GATEWAY_PID=$!
    cd - >/dev/null
    
    # Wait for gateway to start
    log "Waiting for gateway to initialize..."
    for i in {1..30}; do
        if curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1; then
            success "Gateway started successfully (PID: $GATEWAY_PID)"
            return 0
        fi
        sleep 1
    done
    
    error "Gateway failed to start within 30 seconds"
    cat gateway.log
    exit 1
}

# Test nonce recovery
test_nonce_recovery() {
    log "Starting nonce desynchronization test..."
    
    # Initial health check
    log "Performing initial health check..."
    if ! curl -s "$TEST_API_ENDPOINT" >/dev/null; then
        error "Initial health check failed"
        return 1
    fi
    success "Initial health check passed"
    
    # Kill dashboard to simulate restart
    log "Killing dashboard to simulate restart..."
    kill $DASHBOARD_PID
    wait $DASHBOARD_PID 2>/dev/null || true
    DASHBOARD_PID=""
    
    sleep 2
    
    # Restart dashboard (this invalidates nonces)
    log "Restarting dashboard (nonces now invalid)..."
    start_dashboard
    
    # Give some time for the restart
    sleep 3
    
    # Trigger policy/API loading that should cause nonce failure and recovery
    log "Triggering operations that require dashboard communication..."
    
    # Check gateway logs for recovery patterns
    log "Monitoring gateway logs for auto-recovery..."
    
    # Wait and watch for recovery patterns in logs
    local recovery_detected=false
    local recovery_successful=false
    
    for i in {1..60}; do  # Wait up to 60 seconds
        if grep -q "No node ID Found\|nonce.*failed\|Dashboard nonce failure detected" gateway.log; then
            if ! $recovery_detected; then
                success "Nonce failure detected in logs"
                recovery_detected=true
            fi
        fi
        
        if grep -q "Node re-registered successfully" gateway.log; then
            if ! $recovery_successful; then
                success "Auto-recovery completed successfully"
                recovery_successful=true
                break
            fi
        fi
        
        # Try to trigger the issue by making requests that require dashboard communication
        curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1 || true
        
        sleep 1
    done
    
    # Final verification
    log "Performing final verification..."
    if curl -s "$TEST_API_ENDPOINT" >/dev/null; then
        success "Final health check passed - service restored"
        return 0
    else
        error "Final health check failed - service not restored"
        return 1
    fi
}

# Show relevant log entries
show_recovery_logs() {
    log "Showing relevant recovery log entries..."
    echo
    echo "=== Gateway Recovery Logs ==="
    grep -E "(nonce|No node ID|re-register|Network error|Dashboard.*failure)" gateway.log || echo "No recovery logs found"
    echo
    echo "=== Dashboard Logs ==="
    grep -E "(register|node|error)" dashboard.log | tail -10 || echo "No relevant dashboard logs found"
    echo
}

# Main execution
main() {
    log "Starting nonce desynchronization recovery test"
    log "============================================"
    
    check_prerequisites
    build_dashboard
    build_gateway
    
    start_dashboard
    start_gateway
    
    # Let everything stabilize
    log "Allowing services to stabilize..."
    sleep 5
    
    if test_nonce_recovery; then
        success "✅ Nonce recovery test PASSED"
        show_recovery_logs
        exit 0
    else
        error "❌ Nonce recovery test FAILED"
        show_recovery_logs
        exit 1
    fi
}

# Run main function
main "$@"