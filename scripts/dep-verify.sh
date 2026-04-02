#!/bin/bash
# Verify all current deps across all ecosystems present in this repo
set -euo pipefail

FAILED=0

# Go
if [ -f go.mod ]; then
  echo "-- Go: go mod verify ---------------------------------------------------------------"
  go mod verify || FAILED=1
  echo "-- Go: govulncheck -----------------------------------------------------------------"
  govulncheck ./... || FAILED=1
fi

# npm
if [ -f package-lock.json ]; then
  echo "-- npm: audit ----------------------------------------------------------------------"
  npm audit || FAILED=1
  echo "-- npm: provenance -----------------------------------------------------------------"
  npm audit signatures || FAILED=1
fi

# Python
if [ -f requirements.txt ]; then
  echo "-- Python: pip-audit ---------------------------------------------------------------"
  pip-audit -r requirements.txt || FAILED=1
fi

# OSV - runs across all lockfiles in one pass
echo "-- OSV scanner (all ecosystems) ----------------------------------------------------"
osv-scanner scan . || FAILED=1

if [ $FAILED -ne 0 ]; then
  echo ""
  echo "One or more verification checks failed. Review output above."
  exit 1
fi

echo ""
echo "All verification checks passed."
