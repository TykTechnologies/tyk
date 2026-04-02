#!/bin/bash
set -euo pipefail

DOMAIN_FILE="/tmp/.firewall-domains"

if [ ! -f "$DOMAIN_FILE" ]; then
  echo "Domain list not found. Run init-firewall.sh first."
  exit 1
fi

# Create a temporary ipset, populate it, then swap atomically
ipset create allowed-domains-new hash:net 2>/dev/null || ipset flush allowed-domains-new

# Re-add GitHub ranges
gh_ranges=$(curl -s --connect-timeout 10 https://api.github.com/meta 2>/dev/null) || true
if [ -n "$gh_ranges" ]; then
  echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | while read -r cidr; do
    ipset add allowed-domains-new "$cidr" 2>/dev/null || true
  done
fi

# Re-resolve all domains
while IFS= read -r domain; do
  ips=$(dig +noall +answer +short A "$domain" 2>/dev/null || true)
  if [ -z "$ips" ]; then
    echo "$(date): WARNING: No A records for $domain" >> /var/log/firewall-refresh.log
    continue
  fi
  echo "$ips" | while read -r ip; do
    [ -n "$ip" ] && ipset add allowed-domains-new "$ip" 2>/dev/null || true
  done
done < "$DOMAIN_FILE"

# Re-add host network
HOST_IP=$(ip route | grep default | cut -d" " -f3)
HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
ipset add allowed-domains-new "$HOST_NETWORK" 2>/dev/null || true

# Atomic swap
ipset swap allowed-domains-new allowed-domains
ipset destroy allowed-domains-new 2>/dev/null || true

echo "$(date): Firewall IPs refreshed"
