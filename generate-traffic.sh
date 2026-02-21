#!/bin/bash

# Traffic Generator for Tyk Quickstart Endpoint
# Usage: ./generate-traffic.sh [OPTIONS]

set -e

# Default configuration
ENDPOINT="${ENDPOINT:-http://localhost:9009/quickstart/}"
REQUESTS="${REQUESTS:-100}"
CONCURRENT="${CONCURRENT:-1}"
DELAY="${DELAY:-0.1}"
VERBOSE="${VERBOSE:-false}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display usage
usage() {
    cat << EOF
Traffic Generator for Tyk Gateway

Usage: $0 [OPTIONS]

Options:
    -e, --endpoint URL       Target endpoint (default: http://localhost:9009/quickstart/)
    -n, --requests NUM       Number of requests to make (default: 100)
    -c, --concurrent NUM     Number of concurrent requests (default: 1)
    -d, --delay SECONDS      Delay between requests in seconds (default: 0.1)
    -v, --verbose            Enable verbose output
    -h, --help               Show this help message

Environment Variables:
    ENDPOINT                 Same as --endpoint
    REQUESTS                 Same as --requests
    CONCURRENT               Same as --concurrent
    DELAY                    Same as --delay
    VERBOSE                  Set to 'true' for verbose output

Examples:
    # Generate 100 requests with default settings
    $0

    # Generate 1000 requests with 10 concurrent connections
    $0 -n 1000 -c 10

    # Custom endpoint with verbose output
    $0 -e http://localhost:8080/api/test -v

    # High traffic simulation (1000 requests, 50 concurrent, no delay)
    $0 -n 1000 -c 50 -d 0

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        -n|--requests)
            REQUESTS="$2"
            shift 2
            ;;
        -c|--concurrent)
            CONCURRENT="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            usage
            ;;
    esac
done

# Validate inputs
if ! [[ "$REQUESTS" =~ ^[0-9]+$ ]] || [ "$REQUESTS" -lt 1 ]; then
    echo -e "${RED}Error: REQUESTS must be a positive integer${NC}"
    exit 1
fi

if ! [[ "$CONCURRENT" =~ ^[0-9]+$ ]] || [ "$CONCURRENT" -lt 1 ]; then
    echo -e "${RED}Error: CONCURRENT must be a positive integer${NC}"
    exit 1
fi

# Statistics
SUCCESS_COUNT=0
FAIL_COUNT=0
TOTAL_TIME=0
START_TIME=$(date +%s)

# Temporary file for parallel processing
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Function to make a single request
make_request() {
    local request_id=$1
    local start=$(date +%s.%N)

    if [ "$VERBOSE" = true ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$ENDPOINT" 2>&1)
        status_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')

        end=$(date +%s.%N)
        duration=$(echo "$end - $start" | bc)

        echo -e "${BLUE}[Request $request_id]${NC} Status: $status_code | Duration: ${duration}s"
        if [ ${#body} -gt 0 ] && [ ${#body} -lt 200 ]; then
            echo -e "${YELLOW}Response: $body${NC}"
        fi
    else
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$ENDPOINT" 2>&1)
        end=$(date +%s.%N)
        duration=$(echo "$end - $start" | bc)
    fi

    # Write result to temp file
    echo "$status_code|$duration" > "$TEMP_DIR/$request_id"
}

# Print configuration
echo -e "${GREEN}=== Tyk Traffic Generator ===${NC}"
echo -e "Endpoint:    ${BLUE}$ENDPOINT${NC}"
echo -e "Requests:    ${BLUE}$REQUESTS${NC}"
echo -e "Concurrent:  ${BLUE}$CONCURRENT${NC}"
echo -e "Delay:       ${BLUE}${DELAY}s${NC}"
echo -e "Verbose:     ${BLUE}$VERBOSE${NC}"
echo ""

# Generate traffic
echo -e "${YELLOW}Generating traffic...${NC}"
echo ""

for ((i=1; i<=REQUESTS; i++)); do
    # Launch request in background if concurrent
    if [ "$CONCURRENT" -gt 1 ]; then
        # Wait if we've reached concurrent limit
        while [ $(jobs -r | wc -l) -ge "$CONCURRENT" ]; do
            sleep 0.01
        done
        make_request $i &
    else
        make_request $i
    fi

    # Progress indicator (every 10%)
    if [ $((i % (REQUESTS / 10 + 1))) -eq 0 ] && [ "$VERBOSE" = false ]; then
        progress=$((i * 100 / REQUESTS))
        echo -ne "\rProgress: ${progress}% ($i/$REQUESTS)"
    fi

    # Delay between requests
    if [ "$DELAY" != "0" ] && [ "$CONCURRENT" -eq 1 ]; then
        sleep "$DELAY"
    fi
done

# Wait for all background jobs to complete
wait

if [ "$VERBOSE" = false ]; then
    echo -ne "\rProgress: 100% ($REQUESTS/$REQUESTS)\n"
fi

echo ""
echo -e "${YELLOW}Processing results...${NC}"

# Collect statistics from temp files
TOTAL_DURATION=0
MIN_DURATION=999999
MAX_DURATION=0

for file in "$TEMP_DIR"/*; do
    if [ -f "$file" ]; then
        IFS='|' read -r status duration < "$file"

        if [ "$status" = "200" ]; then
            ((SUCCESS_COUNT++))
        else
            ((FAIL_COUNT++))
        fi

        TOTAL_DURATION=$(echo "$TOTAL_DURATION + $duration" | bc)

        if [ $(echo "$duration < $MIN_DURATION" | bc) -eq 1 ]; then
            MIN_DURATION=$duration
        fi

        if [ $(echo "$duration > $MAX_DURATION" | bc) -eq 1 ]; then
            MAX_DURATION=$duration
        fi
    fi
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Calculate average
if [ "$SUCCESS_COUNT" -gt 0 ]; then
    AVG_DURATION=$(echo "scale=4; $TOTAL_DURATION / $SUCCESS_COUNT" | bc)
else
    AVG_DURATION=0
fi

# Calculate requests per second
if [ "$ELAPSED" -gt 0 ]; then
    RPS=$(echo "scale=2; $REQUESTS / $ELAPSED" | bc)
else
    RPS=0
fi

# Display results
echo ""
echo -e "${GREEN}=== Results ===${NC}"
echo -e "Total Requests:  ${BLUE}$REQUESTS${NC}"
echo -e "Successful:      ${GREEN}$SUCCESS_COUNT${NC}"
echo -e "Failed:          ${RED}$FAIL_COUNT${NC}"
echo -e "Success Rate:    ${BLUE}$(echo "scale=2; $SUCCESS_COUNT * 100 / $REQUESTS" | bc)%${NC}"
echo ""
echo -e "${GREEN}=== Performance ===${NC}"
echo -e "Total Time:      ${BLUE}${ELAPSED}s${NC}"
echo -e "Requests/sec:    ${BLUE}$RPS${NC}"
if [ "$SUCCESS_COUNT" -gt 0 ]; then
    echo -e "Avg Duration:    ${BLUE}${AVG_DURATION}s${NC}"
    echo -e "Min Duration:    ${BLUE}${MIN_DURATION}s${NC}"
    echo -e "Max Duration:    ${BLUE}${MAX_DURATION}s${NC}"
fi
echo ""

# Exit with error if any requests failed
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}Warning: Some requests failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Traffic generation completed successfully!${NC}"
