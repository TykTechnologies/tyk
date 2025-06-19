#!/bin/bash
# cleanup.sh - Reset everything to original state

echo "Cleaning up test environment..."

# Completely flush and reset firewall rules
echo "Resetting firewall rules..."
sudo pfctl -F all
cat > /tmp/pfrules << EOF
# Default pass rule for all traffic
pass out proto tcp from any to any
EOF
sudo pfctl -f /tmp/pfrules

# Remove alias IP
echo "Removing alias IP 127.0.0.2..."
sudo ifconfig lo0 -alias 127.0.0.2 2>/dev/null || true

# Clean up hosts file
echo "Cleaning up hosts file..."
sudo sed -i '' '/mdcb.local/d' /etc/hosts

# Flush DNS cache
echo "Flushing DNS cache..."
sudo killall -HUP mDNSResponder

# Reset TCP settings if you modified them
echo "Resetting TCP settings to defaults..."
sudo sysctl -w net.inet.tcp.keepidle=7200000
sudo sysctl -w net.inet.tcp.keepintvl=75000
sudo sysctl -w net.inet.tcp.keepcnt=8
sudo sysctl -w net.inet.tcp.msl=15000

echo "Cleanup complete. All changes have been reverted."
echo "Don't forget to restart your applications if needed."