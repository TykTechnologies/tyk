#!/bin/bash

# Continuous Load Testing Script
# This script generates continuous API requests to verify service continuity during failure scenarios

set -e

# Configuration
GATEWAY_PORT=8282
DEFAULT_ENDPOINT="/hello"
DEFAULT_DURATION=60
DEFAULT_RATE=10
STATS_INTERVAL=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
STATS_FILE=""
LOAD_TEST_PID=""
MONITOR_PID=""

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -e, --endpoint ENDPOINT    API endpoint to test (default: $DEFAULT_ENDPOINT)"
    echo "  -p, --port PORT           Gateway port (default: $GATEWAY_PORT)"
    echo "  -d, --duration SECONDS    Test duration in seconds (default: $DEFAULT_DURATION)"
    echo "  -r, --rate RPS            Requests per second (default: $DEFAULT_RATE)"
    echo "  -s, --stats-file FILE     Statistics output file"
    echo "  -v, --verbose             Verbose output"
    echo "  -h, --help               Show this help"
    echo
    echo "Examples:"
    echo "  $0 -d 120 -r 20                    # Run for 2 minutes at 20 RPS"
    echo "  $0 -e /api/health -p 8080          # Test custom endpoint on port 8080"
    echo "  $0 -s results.log -v               # Save stats and show verbose output"
}

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
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

stats() {
    echo -e "${CYAN}[STATS]${NC} $1"
}

# Parse command line arguments
parse_args() {
    ENDPOINT="$DEFAULT_ENDPOINT"
    PORT="$GATEWAY_PORT"
    DURATION="$DEFAULT_DURATION"
    RATE="$DEFAULT_RATE"
    VERBOSE=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--endpoint)
                ENDPOINT="$2"
                shift 2
                ;;
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -r|--rate)
                RATE="$2"
                shift 2
                ;;
            -s|--stats-file)
                STATS_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        error "Invalid port: $PORT"
        exit 1
    fi
    
    if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -lt 1 ]; then
        error "Invalid duration: $DURATION"
        exit 1
    fi
    
    if ! [[ "$RATE" =~ ^[0-9]+$ ]] || [ "$RATE" -lt 1 ]; then
        error "Invalid rate: $RATE"
        exit 1
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up load test processes..."
    
    if [[ -n "$LOAD_TEST_PID" ]]; then
        kill $LOAD_TEST_PID 2>/dev/null || true
        wait $LOAD_TEST_PID 2>/dev/null || true
    fi
    
    if [[ -n "$MONITOR_PID" ]]; then
        kill $MONITOR_PID 2>/dev/null || true
        wait $MONITOR_PID 2>/dev/null || true
    fi
    
    # Clean up temporary files
    rm -f /tmp/load_test_responses_$$ /tmp/load_test_times_$$
    
    success "Load test cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Check if target is reachable
check_target() {
    local url="http://localhost:${PORT}${ENDPOINT}"
    log "Checking target availability: $url"
    
    if curl -s --connect-timeout 5 --max-time 10 "$url" >/dev/null 2>&1; then
        success "Target is reachable"
        return 0
    else
        error "Target is not reachable: $url"
        return 1
    fi
}

# Generate load
generate_load() {
    local url="http://localhost:${PORT}${ENDPOINT}"
    local interval=$(echo "scale=3; 1 / $RATE" | bc -l)
    local response_file="/tmp/load_test_responses_$$"
    local times_file="/tmp/load_test_times_$$"
    
    log "Starting load generation: $RATE RPS for ${DURATION}s to $url"
    
    # Initialize files
    > "$response_file"
    > "$times_file"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local request_count=0
    
    while [[ $(date +%s) -lt $end_time ]]; do
        local request_start=$(date +%s.%N)
        
        # Make request and capture response code and time
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 5 --max-time 10 \
            "$url" 2>/dev/null || echo "000")
        
        local request_end=$(date +%s.%N)
        local response_time=$(echo "$request_end - $request_start" | bc -l)
        
        # Record results
        echo "$response_code" >> "$response_file"
        echo "$response_time" >> "$times_file"
        
        request_count=$((request_count + 1))
        
        if $VERBOSE; then
            printf "Request %d: %s (%.3fs)\n" "$request_count" "$response_code" "$response_time"
        fi
        
        # Sleep for the calculated interval
        sleep "$interval" 2>/dev/null || true
    done
    
    log "Load generation completed: $request_count requests sent"
}

# Monitor statistics
monitor_stats() {
    local response_file="/tmp/load_test_responses_$$"
    local times_file="/tmp/load_test_times_$$"
    
    while true; do
        sleep $STATS_INTERVAL
        
        if [[ -f "$response_file" && -f "$times_file" ]]; then
            calculate_and_display_stats "$response_file" "$times_file"
        fi
    done
}

# Calculate and display statistics
calculate_and_display_stats() {
    local response_file="$1"
    local times_file="$2"
    
    if [[ ! -s "$response_file" ]]; then
        return
    fi
    
    local total_requests=$(wc -l < "$response_file")
    local successful_requests=$(grep -c "^2[0-9][0-9]$" "$response_file" 2>/dev/null || echo "0")
    local error_4xx=$(grep -c "^4[0-9][0-9]$" "$response_file" 2>/dev/null || echo "0")
    local error_5xx=$(grep -c "^5[0-9][0-9]$" "$response_file" 2>/dev/null || echo "0")
    local connection_errors=$(grep -c "^000$" "$response_file" 2>/dev/null || echo "0")
    
    local success_rate=0
    if [[ $total_requests -gt 0 ]]; then
        success_rate=$(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l)
    fi
    
    # Calculate response time statistics
    local avg_response_time=0
    local max_response_time=0
    local min_response_time=999999
    
    if [[ -s "$times_file" ]]; then
        avg_response_time=$(awk '{sum+=$1; if($1>max) max=$1; if($1<min) min=$1} END {printf "%.3f", sum/NR; print ""; printf "%.3f", max; print ""; printf "%.3f", min}' "$times_file" | head -1)
        max_response_time=$(awk '{if($1>max) max=$1} END {printf "%.3f", max}' "$times_file")
        min_response_time=$(awk 'BEGIN{min=999999} {if($1<min) min=$1} END {printf "%.3f", min}' "$times_file")
    fi
    
    # Display statistics
    echo
    stats "=== Load Test Statistics ==="
    stats "Total Requests: $total_requests"
    stats "Successful (2xx): $successful_requests (${success_rate}%)"
    stats "Client Errors (4xx): $error_4xx"
    stats "Server Errors (5xx): $error_5xx"
    stats "Connection Errors: $connection_errors"
    stats "Avg Response Time: ${avg_response_time}s"
    stats "Min Response Time: ${min_response_time}s"
    stats "Max Response Time: ${max_response_time}s"
    stats "=========================="
    echo
    
    # Save to stats file if specified
    if [[ -n "$STATS_FILE" ]]; then
        {
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Load Test Statistics"
            echo "Target: http://localhost:${PORT}${ENDPOINT}"
            echo "Duration: ${DURATION}s, Rate: ${RATE} RPS"
            echo "Total Requests: $total_requests"
            echo "Successful (2xx): $successful_requests (${success_rate}%)"
            echo "Client Errors (4xx): $error_4xx"
            echo "Server Errors (5xx): $error_5xx"
            echo "Connection Errors: $connection_errors"
            echo "Avg Response Time: ${avg_response_time}s"
            echo "Min Response Time: ${min_response_time}s"
            echo "Max Response Time: ${max_response_time}s"
            echo "----------------------------------------"
            echo
        } >> "$STATS_FILE"
    fi
}

# Show final summary
show_final_summary() {
    local response_file="/tmp/load_test_responses_$$"
    local times_file="/tmp/load_test_times_$$"
    
    log "Final load test summary:"
    calculate_and_display_stats "$response_file" "$times_file"
    
    # Analyze error patterns
    if [[ -f "$response_file" ]]; then
        local connection_errors=$(grep -c "^000$" "$response_file" 2>/dev/null || echo "0")
        local total_errors=$(grep -c -v "^2[0-9][0-9]$" "$response_file" 2>/dev/null || echo "0")
        
        if [[ $connection_errors -gt 0 ]]; then
            warning "Detected $connection_errors connection errors - possible network issues"
        fi
        
        if [[ $total_errors -gt $(echo "$DURATION * $RATE * 0.05" | bc -l | cut -d. -f1) ]]; then
            warning "High error rate detected - investigate service health"
        else
            success "Error rate within acceptable limits"
        fi
    fi
}

# Show real-time progress
show_progress() {
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    
    while [[ $(date +%s) -lt $end_time ]]; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        local remaining=$((end_time - current_time))
        
        printf "\rProgress: %ds elapsed, %ds remaining" "$elapsed" "$remaining"
        sleep 1
    done
    echo
}

# Main execution
main() {
    parse_args "$@"
    
    log "Starting continuous load test"
    log "Target: http://localhost:${PORT}${ENDPOINT}"
    log "Duration: ${DURATION}s"
    log "Rate: ${RATE} RPS"
    if [[ -n "$STATS_FILE" ]]; then
        log "Stats file: $STATS_FILE"
    fi
    
    # Check target availability
    if ! check_target; then
        error "Cannot proceed - target not available"
        exit 1
    fi
    
    # Start statistics monitoring in background
    monitor_stats &
    MONITOR_PID=$!
    
    # Start progress display in background
    if ! $VERBOSE; then
        show_progress &
    fi
    
    # Generate load
    generate_load &
    LOAD_TEST_PID=$!
    
    # Wait for load generation to complete
    wait $LOAD_TEST_PID
    LOAD_TEST_PID=""
    
    # Stop monitoring
    if [[ -n "$MONITOR_PID" ]]; then
        kill $MONITOR_PID 2>/dev/null || true
        MONITOR_PID=""
    fi
    
    # Show final summary
    show_final_summary
    
    success "Load test completed successfully"
}

# Check if bc is available (needed for calculations)
if ! command -v bc >/dev/null 2>&1; then
    error "bc (basic calculator) is required but not installed"
    error "Please install bc: brew install bc (macOS) or apt-get install bc (Ubuntu)"
    exit 1
fi

# Run main function
main "$@"