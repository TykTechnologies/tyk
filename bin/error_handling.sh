#!/bin/bash

# Function to display an error message
display_error_message() {
    local message="$1"
    echo "Error: $message" >&2
}

# Function to exit the script with an error code
exit_with_error() {
    local error_code="$1"
    exit "$error_code"
}
