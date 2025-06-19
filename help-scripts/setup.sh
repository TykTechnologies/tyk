#!/bin/bash
# setup.sh - Set up initial environment for RPC connection testing

echo "Setting up test environment..."

# Add a second IP address to loopback interface
echo "Adding 127.0.0.2 to loopback interface..."
sudo ifconfig lo0 alias 127.0.0.2 up
if [ $? -ne 0 ]; then
    echo "Error: Failed to add alias IP. Exiting."
    exit 1
fi

# Verify both IPs are available
echo "Verifying loopback interface configuration:"
ifconfig lo0

# Update hosts file to point mdcb.local to first IP
echo "Updating /etc/hosts to point mdcb.local to 127.0.0.1..."
sudo sed -i '' '/mdcb.local/d' /etc/hosts
sudo sh -c 'echo "127.0.0.1 mdcb.local" >> /etc/hosts'

# Flush DNS cache
echo "Flushing DNS cache..."
sudo killall -HUP mDNSResponder

echo "Setup complete. mdcb.local now points to 127.0.0.1"
echo "You can now start your MDCB and Gateway applications."
