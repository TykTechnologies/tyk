#!/bin/bash
# scripts/ai-review.sh
# Sends the dep diff to Claude for security analysis
# Requires ANTHROPIC_API_KEY - a scoped key provisioned for dep review only
#
# NOTE: AI review is planned for Phase 2. This script is a no-op stub.
# Uncomment the body below when ANTHROPIC_API_KEY provisioning is in place.

echo "(AI review not yet enabled — skipping)"
exit 0

# --- Uncomment below to enable AI-assisted diff review ---

# DIFF_FILE=$1
# LANG=${2:-"unknown"}
#
# if [ ! -s "$DIFF_FILE" ]; then
#   echo "No diff to review."
#   exit 0
# fi
#
# if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
#   echo "(AI review skipped - ANTHROPIC_API_KEY not set)"
#   exit 0
# fi
#
# DIFF=$(cat "$DIFF_FILE")
#
# RESPONSE=$(curl -s https://api.anthropic.com/v1/messages \
#   -H "x-api-key: $ANTHROPIC_API_KEY" \
#   -H "anthropic-version: 2023-06-01" \
#   -H "content-type: application/json" \
#   -d "{
#     \"model\": \"claude-sonnet-4-20250514\",
#     \"max_tokens\": 1024,
#     \"messages\": [{
#       \"role\": \"user\",
#       \"content\": \"You are a supply chain security reviewer. Analyse this $LANG dependency diff for security issues. Look for: new init() functions or equivalent startup hooks, new network calls, new system calls, encoded or obfuscated payloads, new postinstall or preinstall scripts, suspicious new transitive dependencies (especially packages with few downloads or recent creation dates), and anything anomalous for a library of this type. Be concise and specific. If nothing is suspicious, say so clearly. Do NOT say the diff is safe - say you found no obvious indicators. The developer must still review.\n\nDiff:\n$DIFF\"
#     }]
#   }")
#
# echo ""
# echo "-- AI Review (advisory only, not a gate) -------------------------------------------"
# echo "$RESPONSE" | jq -r '.content[0].text'
# echo "------------------------------------------------------------------------------------"
# echo "NOTE: This is an automated signal. You must still review the diff yourself."
# echo ""
