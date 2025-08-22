#!/bin/bash

# Log Monitor Script - Monitors gateway logs for auto-recovery events
# This script provides real-time monitoring and analysis of recovery patterns

# set -e  # Disabled to prevent early exit on grep no-matches

# Configuration
DEFAULT_LOG_FILE="gateway.log"
DEFAULT_FOLLOW_MODE=true
DASHBOARD_LOG_FILE="dashboard.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Global variables
STATS=()
RECOVERY_COUNT=0
NONCE_FAILURES=0
NETWORK_FAILURES=0
RECOVERY_SUCCESSES=0
RECOVERY_FAILURES=0

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -f, --file FILE           Log file to monitor (default: $DEFAULT_LOG_FILE)"
    echo "  -F, --follow             Follow log file (tail -f mode) [default]"
    echo "  -n, --no-follow          Analyze existing log file only"
    echo "  -s, --summary            Show summary statistics only"
    echo "  -d, --dashboard FILE     Also monitor dashboard log file"
    echo "  -t, --timestamps         Show timestamps in output"
    echo "  -c, --color              Force colored output"
    echo "  --no-color              Disable colored output"
    echo "  -h, --help              Show this help"
    echo
    echo "Examples:"
    echo "  $0                                    # Monitor gateway.log in follow mode"
    echo "  $0 -f /var/log/tyk/gateway.log       # Monitor specific log file"
    echo "  $0 -n -s                             # Analyze existing log and show summary"
    echo "  $0 -d dashboard.log -t               # Monitor both logs with timestamps"
}

# Logging functions
log() {
    if [[ "$1" == "-n" ]]; then
        shift
        printf "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
    else
        echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
    fi
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    ((RECOVERY_SUCCESSES++))
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    ((RECOVERY_FAILURES++))
}

nonce_failure() {
    echo -e "${MAGENTA}[NONCE-FAILURE]${NC} $1"
    ((NONCE_FAILURES++))
}

network_failure() {
    echo -e "${YELLOW}[NETWORK-FAILURE]${NC} $1"
    ((NETWORK_FAILURES++))
}

recovery() {
    echo -e "${GREEN}[RECOVERY]${NC} $1"
    ((RECOVERY_COUNT++))
}

# Parse command line arguments
parse_args() {
    LOG_FILE="$DEFAULT_LOG_FILE"
    FOLLOW_MODE="$DEFAULT_FOLLOW_MODE"
    SUMMARY_ONLY=false
    SHOW_TIMESTAMPS=false
    USE_COLOR=true
    
    # Check if output is a terminal
    if [[ ! -t 1 ]]; then
        USE_COLOR=false
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                LOG_FILE="$2"
                shift 2
                ;;
            -F|--follow)
                FOLLOW_MODE=true
                shift
                ;;
            -n|--no-follow)
                FOLLOW_MODE=false
                shift
                ;;
            -s|--summary)
                SUMMARY_ONLY=true
                shift
                ;;
            -d|--dashboard)
                DASHBOARD_LOG_FILE="$2"
                shift 2
                ;;
            -t|--timestamps)
                SHOW_TIMESTAMPS=true
                shift
                ;;
            -c|--color)
                USE_COLOR=true
                shift
                ;;
            --no-color)
                USE_COLOR=false
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
    
    # Disable colors if requested
    if ! $USE_COLOR; then
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
    fi
}

# Process a log line
process_log_line() {
    local line="$1"
    local source="$2"
    local timestamp=""
    
    if $SHOW_TIMESTAMPS; then
        timestamp="[$(date +'%H:%M:%S')] "
    fi
    
    # Extract timestamp from log line if present
    local log_timestamp=""
    if [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
        log_timestamp=$(echo "$line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}')
        if $SHOW_TIMESTAMPS; then
            timestamp="[$log_timestamp] "
        fi
    fi
    
    # Pattern matching for recovery events
    case "$line" in
        *"No node ID Found"*)
            nonce_failure "${timestamp}${source}No node ID Found error detected"
            ;;
        *"nonce failed"*|*"Nonce failed"*)
            nonce_failure "${timestamp}${source}Nonce validation failure detected"
            ;;
        *"Dashboard nonce failure detected"*)
            nonce_failure "${timestamp}${source}Dashboard nonce failure detected, initiating recovery"
            ;;
        *"Network error detected during policy fetch"*)
            network_failure "${timestamp}${source}Network error during policy fetch"
            ;;
        *"Network error detected while reading"*)
            network_failure "${timestamp}${source}Network error during response reading"
            ;;
        *"Policy request failed"*)
            if [[ "$line" =~ (connection|timeout|EOF|refused) ]]; then
                network_failure "${timestamp}${source}Policy request failed due to network issue"
            else
                warning "${timestamp}${source}Policy request failed: $(echo "$line" | grep -o 'Policy request failed.*')"
            fi
            ;;
        *"attempting to re-register node"*)
            info "${timestamp}${source}Auto-recovery attempt initiated"
            ;;
        *"Node re-registered successfully"*)
            if [[ "$line" =~ "network error" ]]; then
                success "${timestamp}${source}Successfully recovered from network error"
            elif [[ "$line" =~ "nonce" ]] || [[ "$line" =~ previous ]]; then
                success "${timestamp}${source}Successfully recovered from nonce failure"
            else
                success "${timestamp}${source}Node re-registration successful"
            fi
            ;;
        *"retrying policy fetch"*|*"retrying.*fetch"*)
            recovery "${timestamp}${source}Retrying operation after recovery"
            ;;
        *"Failed to re-register node"*)
            error "${timestamp}${source}Auto-recovery failed: $(echo "$line" | grep -o 'Failed to re-register.*')"
            ;;
        *"connection refused"*|*"connection closed"*|*"connection reset"*)
            network_failure "${timestamp}${source}Connection error: $(echo "$line" | grep -oE '(connection [^[:space:]]*|Connection [^[:space:]]*)')"
            ;;
        *"timeout"*|*"Timeout"*)
            if [[ "$line" =~ (dashboard|policy|api) ]]; then
                network_failure "${timestamp}${source}Timeout during dashboard communication"
            fi
            ;;
        *"EOF"*|*"unexpected EOF"*)
            if [[ "$line" =~ (policy|api|dashboard) ]]; then
                network_failure "${timestamp}${source}Unexpected connection termination (EOF)"
            fi
            ;;
    esac
}

# Monitor log file
monitor_log() {
    local log_file="$1"
    local source_prefix="$2"
    
    if [[ ! -f "$log_file" ]]; then
        error "Log file not found: $log_file"
        return 1
    fi
    
    if $FOLLOW_MODE; then
        log "Monitoring $log_file in follow mode (Press Ctrl+C to stop)..."
        tail -f "$log_file" | while IFS= read -r line; do
            process_log_line "$line" "$source_prefix"
        done
    else
        log "Analyzing existing log file: $log_file"
        while IFS= read -r line; do
            process_log_line "$line" "$source_prefix"
        done < "$log_file"
    fi
}

# Show statistics summary
show_summary() {
    echo
    echo -e "${BOLD}=== Recovery Monitoring Summary ===${NC}"
    echo -e "${BLUE}Total Recovery Events:${NC} $RECOVERY_COUNT"
    echo -e "${MAGENTA}Nonce Failures Detected:${NC} $NONCE_FAILURES"
    echo -e "${YELLOW}Network Failures Detected:${NC} $NETWORK_FAILURES"
    echo -e "${GREEN}Successful Recoveries:${NC} $RECOVERY_SUCCESSES"
    echo -e "${RED}Failed Recoveries:${NC} $RECOVERY_FAILURES"
    
    # Calculate success rate
    local total_recovery_attempts=$((RECOVERY_SUCCESSES + RECOVERY_FAILURES))
    if [[ $total_recovery_attempts -gt 0 ]]; then
        local success_rate=$(echo "scale=1; $RECOVERY_SUCCESSES * 100 / $total_recovery_attempts" | bc -l 2>/dev/null || echo "N/A")
        echo -e "${CYAN}Recovery Success Rate:${NC} ${success_rate}%"
    else
        echo -e "${CYAN}Recovery Success Rate:${NC} N/A (no recovery attempts detected)"
    fi
    
    echo -e "${BOLD}===================================${NC}"
    echo
    
    # Provide recommendations
    if [[ $RECOVERY_FAILURES -gt $RECOVERY_SUCCESSES ]] && [[ $RECOVERY_FAILURES -gt 0 ]]; then
        warning "High recovery failure rate detected - investigate dashboard connectivity"
    elif [[ $NETWORK_FAILURES -gt 10 ]]; then
        warning "High number of network failures - check network stability"
    elif [[ $RECOVERY_SUCCESSES -gt 0 ]]; then
        success "Auto-recovery mechanism is working as expected"
    fi
}

# Monitor multiple files
monitor_multiple_files() {
    if [[ -n "$DASHBOARD_LOG_FILE" ]] && [[ -f "$DASHBOARD_LOG_FILE" ]]; then
        log "Starting dual log monitoring..."
        log "Gateway log: $LOG_FILE"
        log "Dashboard log: $DASHBOARD_LOG_FILE"
        echo
        
        if $FOLLOW_MODE; then
            # Monitor both files simultaneously
            (monitor_log "$LOG_FILE" "[GW] ") &
            local GW_PID=$!
            
            (monitor_log "$DASHBOARD_LOG_FILE" "[DASH] ") &
            local DASH_PID=$!
            
            # Wait for both processes
            wait $GW_PID $DASH_PID
        else
            # Analyze both files sequentially
            monitor_log "$LOG_FILE" "[GW] "
            monitor_log "$DASHBOARD_LOG_FILE" "[DASH] "
        fi
    else
        # Monitor single file
        log "Monitoring gateway log: $LOG_FILE"
        echo
        monitor_log "$LOG_FILE" ""
    fi
}

# Signal handler for graceful shutdown
cleanup() {
    echo
    log "Monitoring stopped by user"
    show_summary
    exit 0
}

trap cleanup INT TERM

# Main execution
main() {
    parse_args "$@"
    
    # Check if bc is available for calculations
    if ! command -v bc >/dev/null 2>&1; then
        warning "bc (basic calculator) not found - success rate calculations will show N/A"
    fi
    
    if $SUMMARY_ONLY; then
        # Just analyze existing file and show summary
        if [[ -f "$LOG_FILE" ]]; then
            FOLLOW_MODE=false
            monitor_log "$LOG_FILE" ""
            show_summary
        else
            error "Log file not found: $LOG_FILE"
            exit 1
        fi
    else
        # Start monitoring
        echo -e "${BOLD}Tyk Gateway Recovery Log Monitor${NC}"
        echo -e "${BOLD}=================================${NC}"
        
        # Show legend
        echo -e "${MAGENTA}[NONCE-FAILURE]${NC} - Nonce validation failures"
        echo -e "${YELLOW}[NETWORK-FAILURE]${NC} - Network communication errors"
        echo -e "${CYAN}[INFO]${NC} - Recovery attempts and general information"
        echo -e "${GREEN}[SUCCESS]${NC} - Successful recovery completions"
        echo -e "${GREEN}[RECOVERY]${NC} - Recovery operations in progress"
        echo -e "${RED}[ERROR]${NC} - Failed recovery attempts"
        echo
        
        monitor_multiple_files
    fi
}

# Run main function
main "$@"