#!/bin/bash
## v2
set -euo pipefail
IFS=$'\n\t'

# Reset default policies to ACCEPT before flushing — on container restart,
# policies from a previous run may still be DROP.
iptables-legacy -P INPUT   ACCEPT
iptables-legacy -P FORWARD ACCEPT
iptables-legacy -P OUTPUT  ACCEPT

# Flush filter and mangle only. NEVER flush nat — Docker's embedded DNS
# at 127.0.0.11 depends on nat rules and cannot be restored.
iptables-legacy -F && iptables-legacy -X
iptables-legacy -t mangle -F && iptables-legacy -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# Allow loopback, DNS (TCP+UDP), and SSH
iptables-legacy -A INPUT  -i lo -j ACCEPT
iptables-legacy -A OUTPUT -o lo -j ACCEPT
iptables-legacy -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables-legacy -A INPUT  -p udp --sport 53 -j ACCEPT
iptables-legacy -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables-legacy -A INPUT  -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables-legacy -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables-legacy -A INPUT  -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Temporary HTTPS access for fetching GitHub IP ranges
iptables-legacy -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables-legacy -A INPUT  -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Build IP allowlist
ipset create allowed-domains hash:net

# GitHub — fetch live IP ranges from GitHub meta API
echo "Fetching GitHub IP ranges..."
gh_ranges=$(curl -sf --connect-timeout 10 https://api.github.com/meta)
echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | while read -r cidr; do
  ipset add allowed-domains "$cidr" 2>/dev/null || true
done

# Tyk-specific allowed domains
# Note: CDN-backed domains rotate IPs frequently. refresh-firewall.sh
# re-resolves these every 30 minutes via cron. If you see intermittent
# failures, run: sudo /usr/local/bin/refresh-firewall.sh
ALLOWED_DOMAINS=(
  "api.anthropic.com"
  "registry.npmjs.org"
  "pypi.org"
  "files.pythonhosted.org"
  "marketplace.visualstudio.com"
  "update.code.visualstudio.com"
)

for domain in "${ALLOWED_DOMAINS[@]}"; do
  echo "Resolving $domain..."
  ips=$(dig +noall +answer A "$domain" | awk '$4 == "A" {print $5}')
  [ -z "$ips" ] && echo "ERROR: Failed to resolve $domain" && exit 1
  echo "$ips" | while read -r ip; do
    ipset add allowed-domains "$ip" 2>/dev/null || true
  done
done

# Persist the domain list for refresh-firewall.sh
printf '%s\n' "${ALLOWED_DOMAINS[@]}" > /tmp/.firewall-domains

# Allow host network (inter-container communication)
HOST_IP=$(ip route | grep default | cut -d" " -f3)
HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
iptables-legacy -A INPUT  -s "$HOST_NETWORK" -j ACCEPT
iptables-legacy -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT

# Remove temporary HTTPS rules
iptables-legacy -D OUTPUT -p tcp --dport 443 -j ACCEPT
iptables-legacy -D INPUT  -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Default-deny, then allow only whitelisted traffic
iptables-legacy -P INPUT   DROP
iptables-legacy -P FORWARD DROP
iptables-legacy -P OUTPUT  DROP
iptables-legacy -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables-legacy -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables-legacy -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT
iptables-legacy -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

# Verify — must NOT be able to reach arbitrary internet
if curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
  echo "ERROR: Firewall verification failed - reached example.com"
  exit 1
fi

# Must still be able to reach GitHub
if ! curl --connect-timeout 5 https://api.github.com/zen >/dev/null 2>&1; then
  echo "ERROR: Firewall verification failed - cannot reach api.github.com"
  exit 1
fi

echo "Firewall configuration complete"
