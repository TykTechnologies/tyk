#!/bin/bash

# Comprehensive Test Suite - Orchestrates all recovery tests
# This script runs all test scenarios and generates a comprehensive report

set -e

# Configuration
RESULTS_DIR="test-results"
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
REPORT_FILE="${RESULTS_DIR}/test-report-${TIMESTAMP}.html"
LOG_FILE="${RESULTS_DIR}/test-execution-${TIMESTAMP}.log"

# Test configuration
CONTINUOUS_LOAD_DURATION=30
CONTINUOUS_LOAD_RATE=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Test results - using simple variables for bash 3.2 compatibility
TEST_DATA_FILE=""
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -q, --quick              Quick test mode (reduced durations)"
    echo "  -s, --skip-load          Skip load balancer tests (require nginx)"
    echo "  -n, --skip-network       Skip network failure tests (require sudo)"
    echo "  -r, --results-dir DIR    Results directory (default: $RESULTS_DIR)"
    echo "  -d, --duration SECONDS   Load test duration (default: $CONTINUOUS_LOAD_DURATION)"
    echo "  -c, --rate RPS           Load test rate (default: $CONTINUOUS_LOAD_RATE)"
    echo "  --html-report           Generate HTML report (default)"
    echo "  --no-html              Skip HTML report generation"
    echo "  -v, --verbose           Verbose output"
    echo "  -h, --help              Show this help"
    echo
    echo "Examples:"
    echo "  $0                      # Run all tests with default settings"
    echo "  $0 -q -s               # Quick mode, skip load balancer tests"
    echo "  $0 -n -d 60            # Skip network tests, 60s load duration"
    echo "  $0 -r /tmp/results     # Save results to /tmp/results"
}

# Logging functions
log() {
    local message="[$(date +'%H:%M:%S')] $1"
    echo -e "${BLUE}${message}${NC}" | tee -a "$LOG_FILE"
}

success() {
    local message="[SUCCESS] $1"
    echo -e "${GREEN}${message}${NC}" | tee -a "$LOG_FILE"
}

error() {
    local message="[ERROR] $1"
    echo -e "${RED}${message}${NC}" | tee -a "$LOG_FILE"
}

warning() {
    local message="[WARNING] $1"
    echo -e "${YELLOW}${message}${NC}" | tee -a "$LOG_FILE"
}

info() {
    local message="[INFO] $1"
    echo -e "${CYAN}${message}${NC}" | tee -a "$LOG_FILE"
}

# Parse command line arguments
parse_args() {
    QUICK_MODE=false
    SKIP_LOAD_TESTS=false
    SKIP_NETWORK_TESTS=false
    GENERATE_HTML=true
    VERBOSE=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -s|--skip-load)
                SKIP_LOAD_TESTS=true
                shift
                ;;
            -n|--skip-network)
                SKIP_NETWORK_TESTS=true
                shift
                ;;
            -r|--results-dir)
                RESULTS_DIR="$2"
                shift 2
                ;;
            -d|--duration)
                CONTINUOUS_LOAD_DURATION="$2"
                shift 2
                ;;
            -c|--rate)
                CONTINUOUS_LOAD_RATE="$2"
                shift 2
                ;;
            --html-report)
                GENERATE_HTML=true
                shift
                ;;
            --no-html)
                GENERATE_HTML=false
                shift
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
    
    # Adjust settings for quick mode
    if $QUICK_MODE; then
        CONTINUOUS_LOAD_DURATION=15
        CONTINUOUS_LOAD_RATE=3
        # Will log this after setup_test_environment
    fi
    
    # Update file paths with new results directory
    REPORT_FILE="${RESULTS_DIR}/test-report-${TIMESTAMP}.html"
    LOG_FILE="${RESULTS_DIR}/test-execution-${TIMESTAMP}.log"
}

# Setup test environment
setup_test_environment() {
    log "Setting up test environment..."
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    # Initialize log file and test data file
    echo "Tyk Gateway Recovery Test Suite" > "$LOG_FILE"
    echo "Started: $(date)" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Initialize test data file
    TEST_DATA_FILE="${RESULTS_DIR}/test-data-${TIMESTAMP}.txt"
    > "$TEST_DATA_FILE"
    
    # Log quick mode if enabled
    if $QUICK_MODE; then
        info "Quick mode enabled - reduced test durations"
    fi
    
    # Check prerequisites
    local missing_deps=()
    
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if ! command -v bc >/dev/null 2>&1; then
        missing_deps+=("bc")
    fi
    
    if ! redis-cli ping >/dev/null 2>&1; then
        error "Redis is not running. Please start Redis first."
        exit 1
    fi
    
    if ! $SKIP_NETWORK_TESTS; then
        if ! command -v toxiproxy-server >/dev/null 2>&1 || ! command -v toxiproxy-cli >/dev/null 2>&1; then
            warning "Toxiproxy not available - will skip network tests"
            SKIP_NETWORK_TESTS=true
        fi
    fi
    
    if ! $SKIP_LOAD_TESTS && ! command -v nginx >/dev/null 2>&1; then
        warning "Nginx not available - will skip load balancer tests"
        SKIP_LOAD_TESTS=true
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi
    
    success "Test environment setup completed"
}

# Store test result in data file
store_test_result() {
    local test_name="$1"
    local test_result="$2"
    local duration="$3"
    local details="$4"
    
    echo "${test_name}|${test_result}|${duration}|${details}" >> "$TEST_DATA_FILE"
}

# Get test result from data file
get_test_result() {
    local test_name="$1"
    local field="$2"  # result, duration, or details
    
    local line=$(grep "^${test_name}|" "$TEST_DATA_FILE" 2>/dev/null || echo "")
    if [[ -n "$line" ]]; then
        case "$field" in
            "result") echo "$line" | cut -d'|' -f2 ;;
            "duration") echo "$line" | cut -d'|' -f3 ;;
            "details") echo "$line" | cut -d'|' -f4- ;;
        esac
    fi
}

# Run a single test
run_test() {
    local test_name="$1"
    local test_script="$2"
    local test_args="${3:-}"
    
    log "Starting test: $test_name"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local start_time=$(date +%s)
    local test_output_file="${RESULTS_DIR}/${test_name}-output-${TIMESTAMP}.log"
    local test_result="UNKNOWN"
    local test_details=""
    
    # Check if test script exists
    if [[ ! -f "$test_script" ]]; then
        test_result="SKIPPED"
        test_details="Test script not found: $test_script"
        warning "Test skipped: $test_name - script not found"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    else
        # Run the test
        if $VERBOSE; then
            info "Executing: $test_script $test_args"
        fi
        
        if bash "$test_script" $test_args > "$test_output_file" 2>&1; then
            test_result="PASSED"
            success "Test passed: $test_name"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            test_result="FAILED"
            error "Test failed: $test_name"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            
            # Extract error details from output
            test_details=$(tail -5 "$test_output_file" | tr '\n' ' ')
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Store results in data file
    store_test_result "$test_name" "$test_result" "$duration" "$test_details"
    
    info "Test completed: $test_name ($duration seconds)"
    echo "" | tee -a "$LOG_FILE"
}

# Run all tests
run_all_tests() {
    log "Starting comprehensive test suite execution"
    echo "==========================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # Test 1: Nonce Recovery Test
    run_test "nonce-recovery" "./test-nonce-recovery.sh"
    
    # Test 2: Network Failure Tests
    if $SKIP_NETWORK_TESTS; then
        log "Skipping network failure tests (toxiproxy not available or disabled)"
        store_test_result "network-failures" "SKIPPED" "0" "Skipped - toxiproxy not available"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
    else
        run_test "network-failures" "./test-network-failures-toxiproxy.sh"
    fi
    
    # Test 3: Load Balancer Drain Tests
    if $SKIP_LOAD_TESTS; then
        log "Skipping load balancer drain tests (nginx not available or disabled)"
        store_test_result "loadbalancer-drain" "SKIPPED" "0" "Skipped - nginx not available"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
    else
        run_test "loadbalancer-drain" "./test-loadbalancer-drain.sh"
    fi
    
    # Test 4: Continuous Load Test (as part of comprehensive testing)
    log "Running continuous load test as stability verification"
    run_test "continuous-load" "./continuous-load-test.sh" "-d $CONTINUOUS_LOAD_DURATION -r $CONTINUOUS_LOAD_RATE -s ${RESULTS_DIR}/load-test-stats-${TIMESTAMP}.log"
}

# Generate summary report
generate_summary() {
    log "Generating test summary..."
    
    local total_duration=0
    if [[ -f "$TEST_DATA_FILE" ]]; then
        while IFS='|' read -r test_name result duration details; do
            total_duration=$((total_duration + duration))
        done < "$TEST_DATA_FILE"
    fi
    
    echo "" | tee -a "$LOG_FILE"
    echo "=========================================" | tee -a "$LOG_FILE"
    echo "TEST EXECUTION SUMMARY" | tee -a "$LOG_FILE"
    echo "=========================================" | tee -a "$LOG_FILE"
    echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
    echo "Total Tests: $TOTAL_TESTS" | tee -a "$LOG_FILE"
    echo "Passed: $PASSED_TESTS" | tee -a "$LOG_FILE"
    echo "Failed: $FAILED_TESTS" | tee -a "$LOG_FILE"
    echo "Skipped: $SKIPPED_TESTS" | tee -a "$LOG_FILE"
    echo "Total Duration: ${total_duration} seconds" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    
    # Detailed results
    echo "DETAILED RESULTS:" | tee -a "$LOG_FILE"
    echo "-----------------" | tee -a "$LOG_FILE"
    
    if [[ -f "$TEST_DATA_FILE" ]]; then
        while IFS='|' read -r test_name result duration details; do
            case "$result" in
                "PASSED")
                    echo -e "${GREEN}✓${NC} $test_name: $result (${duration}s)" | tee -a "$LOG_FILE"
                    ;;
                "FAILED")
                    echo -e "${RED}✗${NC} $test_name: $result (${duration}s)" | tee -a "$LOG_FILE"
                    if [[ -n "$details" ]]; then
                        echo "  Details: $details" | tee -a "$LOG_FILE"
                    fi
                    ;;
                "SKIPPED")
                    echo -e "${YELLOW}⊝${NC} $test_name: $result" | tee -a "$LOG_FILE"
                    if [[ -n "$details" ]]; then
                        echo "  Reason: $details" | tee -a "$LOG_FILE"
                    fi
                    ;;
            esac
        done < "$TEST_DATA_FILE"
    fi
    
    echo "" | tee -a "$LOG_FILE"
    
    # Overall result
    if [[ $FAILED_TESTS -eq 0 ]]; then
        success "ALL TESTS PASSED! ✅"
        if [[ $SKIPPED_TESTS -gt 0 ]]; then
            info "Note: $SKIPPED_TESTS tests were skipped"
        fi
    elif [[ $PASSED_TESTS -gt $FAILED_TESTS ]]; then
        warning "SOME TESTS FAILED ⚠️  ($FAILED_TESTS failed, $PASSED_TESTS passed)"
    else
        error "MULTIPLE TESTS FAILED ❌ ($FAILED_TESTS failed, $PASSED_TESTS passed)"
    fi
}

# Generate HTML report
generate_html_report() {
    if ! $GENERATE_HTML; then
        return 0
    fi
    
    log "Generating HTML report..."
    
    cat > "$REPORT_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tyk Gateway Recovery Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #333; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        .test-results { margin-top: 30px; }
        .test-item { background: #f8f9fa; border-left: 4px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 4px; }
        .test-item.passed { border-left-color: #28a745; }
        .test-item.failed { border-left-color: #dc3545; }
        .test-item.skipped { border-left-color: #ffc107; }
        .test-name { font-weight: bold; font-size: 1.1em; margin-bottom: 5px; }
        .test-status { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; font-weight: bold; margin-right: 10px; }
        .status-passed { background-color: #28a745; }
        .status-failed { background-color: #dc3545; }
        .status-skipped { background-color: #ffc107; color: #000; }
        .test-duration { color: #666; font-size: 0.9em; }
        .test-details { margin-top: 10px; padding: 10px; background: #e9ecef; border-radius: 4px; font-size: 0.9em; color: #495057; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }
        .chart-container { margin: 20px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Tyk Gateway Recovery Test Report</h1>
            <p>Comprehensive test suite for gateway auto-recovery mechanisms</p>
            <p><strong>Generated:</strong> $(date)</p>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-number">$TOTAL_TESTS</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$PASSED_TESTS</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$FAILED_TESTS</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$SKIPPED_TESTS</div>
                <div class="stat-label">Skipped</div>
            </div>
        </div>
        
        <div class="test-results">
            <h2>📋 Test Results</h2>
EOF

    # Add individual test results
    if [[ -f "$TEST_DATA_FILE" ]]; then
        while IFS='|' read -r test_name result duration details; do
            local css_class=""
            local status_class=""
            local status_text=""
            
            case "$result" in
                "PASSED")
                    css_class="passed"
                    status_class="status-passed"
                    status_text="✓ PASSED"
                    ;;
                "FAILED")
                    css_class="failed"
                    status_class="status-failed"
                    status_text="✗ FAILED"
                    ;;
                "SKIPPED")
                    css_class="skipped"
                    status_class="status-skipped"
                    status_text="⊝ SKIPPED"
                    ;;
            esac
            
            cat >> "$REPORT_FILE" << EOF
            <div class="test-item $css_class">
                <div class="test-name">$test_name</div>
                <span class="test-status $status_class">$status_text</span>
                <span class="test-duration">Duration: ${duration}s</span>
EOF

            if [[ -n "$details" ]]; then
                cat >> "$REPORT_FILE" << EOF
                <div class="test-details">
                    <strong>Details:</strong> $details
                </div>
EOF
            fi
            
            cat >> "$REPORT_FILE" << EOF
            </div>
EOF
        done < "$TEST_DATA_FILE"
    fi
    
    cat >> "$REPORT_FILE" << EOF
        </div>
        
        <div class="footer">
            <p>Report generated by Tyk Gateway Recovery Test Suite</p>
            <p>Test execution logs available in: $LOG_FILE</p>
        </div>
    </div>
</body>
</html>
EOF

    success "HTML report generated: $REPORT_FILE"
}

# Main execution
main() {
    parse_args "$@"
    
    # Create results directory first
    mkdir -p "$RESULTS_DIR"
    
    echo -e "${BOLD}Tyk Gateway Recovery Test Suite${NC}"
    echo -e "${BOLD}================================${NC}"
    echo
    
    setup_test_environment
    run_all_tests
    generate_summary
    generate_html_report
    
    echo "" | tee -a "$LOG_FILE"
    log "Test suite execution completed"
    info "Results saved to: $RESULTS_DIR"
    info "Execution log: $LOG_FILE"
    if $GENERATE_HTML; then
        info "HTML report: $REPORT_FILE"
    fi
    
    # Exit with appropriate code
    if [[ $FAILED_TESTS -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"