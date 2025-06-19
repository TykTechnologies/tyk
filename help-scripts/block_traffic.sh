#!/bin/bash
# block_traffic.sh - Block traffic to first IP on port 9091

echo "Blocking traffic to 127.0.0.1 port 9091..."

# Enable packet filtering if not already enabled
echo "Enabling packet filtering..."
sudo pfctl -e

# Flush all existing rules
echo "Flushing existing firewall rules..."
sudo pfctl -F all

# Create a new rule set with default pass and specific block
echo "Creating new firewall rules..."
cat > /tmp/pfrules << EOF
# Default pass rule for all traffic
pass out proto tcp from any to any

# Block rule for specific traffic
block drop out proto tcp from any to 127.0.0.1 port 9091
EOF

# Load the rules
echo "Loading firewall rules..."
sudo pfctl -f /tmp/pfrules

# Verify the rule is active
echo "Verifying active rules:"
sudo pfctl -sr

echo "Traffic blocking complete."
echo "You should start seeing RPC timeout errors in your Gateway logs within 30 seconds."
echo "These errors should persist for about 15-20 minutes with default TCP settings."