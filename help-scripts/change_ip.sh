#!/bin/bash
# change_ip.sh - Change mdcb.local to point to second IP

echo "Changing mdcb.local to point to 127.0.0.2..."

# Update hosts file to point to the second IP
sudo sed -i '' '/mdcb.local/d' /etc/hosts
sudo sh -c 'echo "127.0.0.2 mdcb.local" >> /etc/hosts'

# Flush DNS cache
echo "Flushing DNS cache..."
sudo killall -HUP mDNSResponder

# Verify the change
echo "Verifying the change:"
ping -c 1 mdcb.local

echo "Change complete. mdcb.local now points to 127.0.0.2"
echo "Note: Existing connections will still use 127.0.0.1"
