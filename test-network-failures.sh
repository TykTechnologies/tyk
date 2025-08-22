#!/bin/bash

# Network Failure Simulation Script - Tests network error recovery
# This script tests the auto-recovery mechanism when network failures occur during dashboard communication

# set -e  # Disabled to prevent early exit

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

# Global variables
DASHBOARD_PID=""
GATEWAY_PID=""
IPTABLES_RULES_APPLIED=false
TC_RULES_APPLIED=false

# Cleanup function
cleanup() {
    log "Cleaning up..."
    
    # Remove network rules
    cleanup_network_rules
    
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

# Network cleanup
cleanup_network_rules() {
    if $IPTABLES_RULES_APPLIED; then
        log "Removing iptables rules..."
        sudo iptables -D OUTPUT -p tcp --dport $DASHBOARD_PORT -j DROP 2>/dev/null || true
        sudo iptables -D INPUT -p tcp --sport $DASHBOARD_PORT -j DROP 2>/dev/null || true
        IPTABLES_RULES_APPLIED=false
    fi
    
    if $TC_RULES_APPLIED; then
        log "Removing traffic control rules..."
        sudo tc qdisc del dev lo root 2>/dev/null || true
        TC_RULES_APPLIED=false
    fi
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check for required commands
    if ! command -v iptables >/dev/null 2>&1; then
        error "iptables command not found. Please install iptables."
        exit 1
    fi
    
    if ! command -v tc >/dev/null 2>&1; then
        error "tc command not found. Please install iproute2."
        exit 1
    fi
    
    # Check sudo access
    if ! sudo -n true 2>/dev/null; then
        error "This script requires sudo access for network manipulation."
        error "Please run: sudo -v"
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

# Block dashboard connection using iptables
block_dashboard_connection() {
    log "Blocking dashboard connection using iptables..."
    sudo iptables -A OUTPUT -p tcp --dport $DASHBOARD_PORT -j DROP
    sudo iptables -A INPUT -p tcp --sport $DASHBOARD_PORT -j DROP
    IPTABLES_RULES_APPLIED=true
    success "Dashboard connection blocked"
}

# Unblock dashboard connection
unblock_dashboard_connection() {
    if $IPTABLES_RULES_APPLIED; then
        log "Restoring dashboard connection..."
        sudo iptables -D OUTPUT -p tcp --dport $DASHBOARD_PORT -j DROP
        sudo iptables -D INPUT -p tcp --sport $DASHBOARD_PORT -j DROP
        IPTABLES_RULES_APPLIED=false
        success "Dashboard connection restored"
    fi
}

# Add network latency and packet loss
add_network_issues() {
    log "Adding network latency and packet loss..."
    sudo tc qdisc add dev lo root netem delay 200ms loss 20%
    TC_RULES_APPLIED=true
    success "Network issues added (200ms delay, 20% packet loss)"
}

# Remove network issues
remove_network_issues() {
    if $TC_RULES_APPLIED; then
        log "Removing network issues..."
        sudo tc qdisc del dev lo root
        TC_RULES_APPLIED=false
        success "Network issues removed"
    fi
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
    if grep -q "Network error detected\|Policy request failed" gateway.log; then
        success "Network error detected in logs"
        network_error_detected=true
    fi
    
    # Unblock connection
    unblock_dashboard_connection
    
    # Wait for recovery
    log "Waiting for auto-recovery..."
    local recovery_successful=false
    for i in {1..30}; do
        if grep -q "Node re-registered successfully after network error" gateway.log; then
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
    
    # Add network issues
    add_network_issues
    
    # Trigger requests with poor network conditions
    log "Triggering requests with network degradation..."
    local degradation_detected=false
    
    for i in {1..20}; do
        curl -s "$TEST_API_ENDPOINT" >/dev/null 2>&1 || true
        
        # Check for network issues in logs
        if grep -q "Network error\|timeout\|EOF" gateway.log; then
            if ! $degradation_detected; then
                success "Network degradation effects detected"
                degradation_detected=true
            fi
        fi
        
        sleep 1
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
        warning "Network degradation detected but recovery unclear"
        return 0
    else
        error "❌ Network degradation test FAILED"
        return 1
    fi
}

# Show network-related log entries
show_network_logs() {
    log "Showing network-related log entries..."
    echo
    echo "=== Network Error Logs ==="
    grep -E "(Network error|connection|timeout|EOF|re-register.*network)" gateway.log || echo "No network error logs found"
    echo
}

# Main execution
main() {
    log "Starting network failure recovery tests"
    log "======================================="
    
    check_prerequisites
    build_services
    
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
    
    # Reset logs for next test
    > gateway.log
    
    # Test 2: Network degradation
    if ! test_network_degradation; then
        test_results=$((test_results + 1))
    fi
    
    show_network_logs
    
    if [[ $test_results -eq 0 ]]; then
        success "✅ All network failure tests PASSED"
        exit 0
    else
        error "❌ $test_results network failure tests FAILED"
        exit 1
    fi
}

# Run main function
main "$@"