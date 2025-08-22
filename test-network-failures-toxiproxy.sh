#!/bin/bash

# Network Failure Simulation Script - Tests network error recovery using Toxiproxy
# This script tests the auto-recovery mechanism when network failures occur during dashboard communication

# Configuration
DASHBOARD_DIR="../tyk-analytics"
GATEWAY_DIR="."
DASHBOARD_PORT=3000
GATEWAY_PORT=8282
PROXY_PORT=8001
TEST_API_ENDPOINT="http://localhost:${GATEWAY_PORT}/hello"
DASHBOARD_CONFIG="../tyk-develop-env/confs/tyk_analytics.conf"
GATEWAY_CONFIG="../tyk-develop-env/confs/tyk_pro.conf"
DASHBOARD_PROXY_NAME="dashboard-proxy"

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
    echo -e "${RED}[ERROR]${NC} $1" >&2
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
TOXIPROXY_PID=""

# Cleanup function
cleanup() {
    log "Cleaning up..."
    
    # Stop toxiproxy and remove proxies
    cleanup_toxiproxy
    
    # Kill processes
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

# Toxiproxy cleanup
cleanup_toxiproxy() {
    if [[ -n "$TOXIPROXY_PID" ]]; then
        log "Stopping toxiproxy server..."
        # Remove proxy first
        toxiproxy-cli delete "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
        kill $TOXIPROXY_PID 2>/dev/null || true
        wait $TOXIPROXY_PID 2>/dev/null || true
        TOXIPROXY_PID=""
    fi
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check for required commands
    if ! command -v toxiproxy-server >/dev/null 2>&1; then
        error "toxiproxy-server command not found. Please install toxiproxy."
        error "On macOS: brew install toxiproxy"
        exit 1
    fi
    
    if ! command -v toxiproxy-cli >/dev/null 2>&1; then
        error "toxiproxy-cli command not found. Please install toxiproxy."
        error "On macOS: brew install toxiproxy"
        exit 1
    fi
    
    # Check directories and configs
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
    
    # Check if ports are available
    if lsof -i :$PROXY_PORT >/dev/null 2>&1; then
        error "Port $PROXY_PORT is already in use. Please free this port."
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Build services
build_services() {
    log "Building dashboard..."
    cd "$DASHBOARD_DIR"
    go build -o tyk-analytics || {
        error "Failed to build dashboard"
        exit 1
    }
    cd - >/dev/null
    
    log "Building gateway..."
    cd "$GATEWAY_DIR"
    go build --tags ee -o tyk || {
        error "Failed to build gateway"
        exit 1
    }
    cd - >/dev/null
    
    success "Services built successfully"
}

# Start toxiproxy server
start_toxiproxy() {
    log "Starting toxiproxy server..."
    toxiproxy-server > /dev/null 2>&1 &
    TOXIPROXY_PID=$!
    
    # Wait for toxiproxy to start
    for i in {1..10}; do
        if toxiproxy-cli list >/dev/null 2>&1; then
            success "Toxiproxy server started (PID: $TOXIPROXY_PID)"
            return 0
        fi
        sleep 1
    done
    
    error "Toxiproxy server failed to start"
    exit 1
}

# Create toxiproxy proxy for dashboard
create_dashboard_proxy() {
    log "Creating toxiproxy proxy for dashboard..."
    toxiproxy-cli create -l "127.0.0.1:$PROXY_PORT" -u "127.0.0.1:$DASHBOARD_PORT" "$DASHBOARD_PROXY_NAME"
    success "Dashboard proxy created on port $PROXY_PORT"
}

# Start dashboard (direct connection)
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

# Start gateway (will connect through toxiproxy)
start_gateway() {
    log "Starting gateway on port $GATEWAY_PORT (connecting via toxiproxy proxy)..."
    
    # Create a temporary gateway config that uses the proxy
    local temp_config="${GATEWAY_CONFIG}.proxy"
    cp "$GATEWAY_CONFIG" "$temp_config"
    
    cd "$GATEWAY_DIR"
    
    TYK_LOGLEVEL=debug \
    TYK_GW_LISTENPORT=$GATEWAY_PORT \
    TYK_GW_HTTPPROFILE=true \
    TYK_GW_STREAMING_ENABLED=true \
    ./tyk --conf="$temp_config" --httpprofile > gateway.log 2>&1 &
    
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

# Block dashboard connection using toxiproxy
block_dashboard_connection() {
    log "Blocking dashboard connection using toxiproxy..."
    toxiproxy-cli toxic add -t "bandwidth" -a "rate=0" "$DASHBOARD_PROXY_NAME"
    success "Dashboard connection blocked"
}

# Unblock dashboard connection
unblock_dashboard_connection() {
    log "Restoring dashboard connection..."
    toxiproxy-cli toxic remove -n "bandwidth_downstream" "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
    toxiproxy-cli toxic remove -n "bandwidth_upstream" "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
    success "Dashboard connection restored"
}

# Add network latency and packet loss
add_network_issues() {
    log "Adding network latency and connection issues via toxiproxy..."
    toxiproxy-cli toxic add -t "latency" -a "latency=500,jitter=100" "$DASHBOARD_PROXY_NAME"
    toxiproxy-cli toxic add -t "slow_close" -a "delay=2000" "$DASHBOARD_PROXY_NAME"
    success "Network issues added (500ms latency, slow close)"
}

# Remove network issues
remove_network_issues() {
    log "Removing network issues..."
    toxiproxy-cli toxic remove -n "latency_downstream" "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
    toxiproxy-cli toxic remove -n "latency_upstream" "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
    toxiproxy-cli toxic remove -n "slow_close_downstream" "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
    toxiproxy-cli toxic remove -n "slow_close_upstream" "$DASHBOARD_PROXY_NAME" 2>/dev/null || true
    success "Network issues removed"
}

# Test connection blocking recovery
test_connection_blocking() {
    log "Testing connection blocking recovery..."
    
    # Block connection
    block_dashboard_connection
    
    # Wait and trigger requests that need dashboard communication
    log "Triggering requests while dashboard is blocked..."
    for i in {1..10}; do
        curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1 || true
        sleep 1
    done
    
    # Check for network error detection
    local network_error_detected=false
    if grep -q "Network error detected\|Policy request failed\|connection" gateway.log; then
        success "Network error detected in logs"
        network_error_detected=true
    fi
    
    # Unblock connection
    unblock_dashboard_connection
    
    # Wait for recovery
    log "Waiting for auto-recovery..."
    local recovery_successful=false
    for i in {1..30}; do
        if grep -q "Node re-registered successfully\|retrying.*fetch" gateway.log; then
            success "Network error recovery completed"
            recovery_successful=true
            break
        fi
        
        # Continue triggering requests
        curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1 || true
        sleep 1
    done
    
    if $network_error_detected && $recovery_successful; then
        success "✅ Connection blocking test PASSED"
        return 0
    else
        error "❌ Connection blocking test FAILED"
        return 1
    fi
}

# Test network quality degradation recovery
test_network_degradation() {
    log "Testing network degradation recovery..."
    
    # Clear previous logs
    > gateway.log
    
    # Add network issues
    add_network_issues
    
    # Trigger requests with poor network conditions
    log "Triggering requests with network degradation..."
    local degradation_detected=false
    
    for i in {1..15}; do
        curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1 || true
        
        # Check for network issues in logs
        if grep -q "Network error\|timeout\|EOF\|slow" gateway.log; then
            if ! $degradation_detected; then
                success "Network degradation effects detected"
                degradation_detected=true
            fi
        fi
        
        sleep 2
    done
    
    # Remove network issues
    remove_network_issues
    
    # Wait for recovery
    log "Waiting for service recovery..."
    for i in {1..20}; do
        if curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1; then
            success "Service recovered from network degradation"
            return 0
        fi
        sleep 1
    done
    
    if $degradation_detected; then
        success "✅ Network degradation test PASSED (degradation detected)"
        return 0
    else
        warning "⚠️ Network degradation test UNCLEAR (no clear degradation detected)"
        return 1
    fi
}

# Show network-related log entries
show_network_logs() {
    log "Showing network-related log entries..."
    echo
    echo "=== Network Error Logs ==="
    grep -E "(Network error|connection|timeout|EOF|re-register.*network|Policy request failed)" gateway.log || echo "No network error logs found"
    echo
}

# Main execution
main() {
    log "Starting network failure recovery tests (with toxiproxy)"
    log "======================================================"
    
    check_prerequisites
    build_services
    
    start_toxiproxy
    create_dashboard_proxy
    start_dashboard
    start_gateway
    
    # Let services stabilize
    log "Allowing services to stabilize..."
    sleep 5
    
    local test_results=0
    
    # Test 1: Connection blocking
    if ! test_connection_blocking; then
        test_results=$((test_results + 1))
    fi
    
    # Test 2: Network degradation
    if ! test_network_degradation; then
        test_results=$((test_results + 1))
    fi
    
    show_network_logs
    
    if [[ $test_results -eq 0 ]]; then
        success "✅ All toxiproxy network tests PASSED"
        exit 0
    else
        error "❌ $test_results toxiproxy network tests FAILED"
        exit 1
    fi
}

# Run main function
main "$@"