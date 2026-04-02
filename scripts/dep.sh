#!/bin/bash
# Add a dependency at a specific pinned version - dispatches by LANG
# Never accepts @latest or version ranges - pinned versions only.
set -euo pipefail

LANG=$1
PKG=$2

# Enforce that PKG contains an explicit version - reject @latest and bare names
if echo "$PKG" | grep -qE "@latest$|^[^@]+$"; then
  echo "ERROR: PKG must include an explicit pinned version."
  echo "  Good: github.com/some/pkg@v1.2.3"
  echo "  Good: lodash@4.17.21"
  echo "  Bad:  github.com/some/pkg@latest"
  echo "  Bad:  lodash"
  exit 1
fi

# Mark that a dependency workflow is active
touch /tmp/.dep-workflow-active
trap 'rm -f /tmp/.dep-workflow-active' EXIT

_scan_and_diff_go() {
  go mod tidy
  go mod verify
  local pkg_module="${1%%@*}"
  local pkg_version="${1##*@}"
  echo "-- Vulnerability scan (govulncheck) for ${pkg_module}@${pkg_version} ----------------"
  govulncheck -scan module || echo "WARNING: govulncheck reported vulnerabilities (review above)"
  echo "-- OSV scan for ${pkg_module}@${pkg_version} ----------------------------------------"
  curl -sf https://api.osv.dev/v1/query \
    -d "{\"package\":{\"name\":\"${pkg_module}\",\"ecosystem\":\"Go\"},\"version\":\"${pkg_version}\"}" \
    | python3 -m json.tool || echo "(no vulnerabilities found)"
  echo "-- Diff ----------------------------------------------------------------------------"
  git diff go.mod go.sum | tee /tmp/.dep-diff.txt
  /scripts/ai-review.sh /tmp/.dep-diff.txt go
}

_scan_and_diff_npm() {
  echo "-- npm audit -----------------------------------------------------------------------"
  npm audit
  echo "-- Provenance check ----------------------------------------------------------------"
  echo "Verifying SLSA provenance attestations..."
  npm audit signatures 2>&1 || echo "WARNING: One or more packages lack provenance attestations. Review carefully."
  echo "-- OSV scan ------------------------------------------------------------------------"
  osv-scanner scan --lockfile package-lock.json .
  echo "-- Diff ----------------------------------------------------------------------------"
  git diff package.json package-lock.json | tee /tmp/.dep-diff.txt
  /scripts/ai-review.sh /tmp/.dep-diff.txt npm
}

_scan_and_diff_python() {
  pip-audit
  echo "-- OSV scan ------------------------------------------------------------------------"
  osv-scanner scan --lockfile requirements.txt .
  echo "-- Diff ----------------------------------------------------------------------------"
  git diff requirements.txt | tee /tmp/.dep-diff.txt
  /scripts/ai-review.sh /tmp/.dep-diff.txt python
}

case "$LANG" in
  go)
    if ! echo "$PKG" | grep -qE '@v[0-9]+\.[0-9]+\.[0-9]+'; then
      echo "ERROR: Go packages must use full semver: @vMAJOR.MINOR.PATCH (e.g., @v1.2.3)"
      exit 1
    fi
    go get "$PKG"
    _scan_and_diff_go "$PKG"
    ;;

  npm)
    if ! echo "$PKG" | grep -qE '@[0-9]+\.[0-9]+\.[0-9]+'; then
      echo "ERROR: npm packages must use full semver: @MAJOR.MINOR.PATCH (e.g., @4.17.21)"
      exit 1
    fi
    # --ignore-scripts: prevents postinstall hooks from executing during review.
    # This is the single control that would have blocked the Axios RAT dropper.
    # --save-exact: pins to the exact version, no semver ranges.
    npm install --ignore-scripts --save-exact "$PKG"
    _scan_and_diff_npm
    ;;

  python)
    if ! echo "$PKG" | grep -qE '==[0-9]+\.[0-9]+'; then
      echo "ERROR: Python packages must pin version: ==MAJOR.MINOR[.PATCH] (e.g., ==2.32.3)"
      exit 1
    fi
    pip install --require-hashes "$PKG"
    _scan_and_diff_python
    ;;

  *)
    echo "Unknown LANG: $LANG. Supported: go, npm, python"
    exit 1
    ;;
esac

echo ""
echo "============================================================================"
echo "  REVIEW CHECKLIST"
echo "============================================================================"
echo "  1. Review scan results above for vulnerabilities and advisories"
echo "  2. Review the diff for unexpected transitive dependencies"
echo "  3. If AI review is enabled, read the AI analysis below"
echo "  4. AI review is an ADDITIONAL signal, not a replacement for your review"
echo "  5. If everything looks clean: commit, open a PR, request tech lead review"
echo "============================================================================"
