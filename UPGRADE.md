# Tyk Gateway Go 1.25.5 Upgrade Process

**Team:** @Engineering @DevOps @QA
**Date:** 2026-01-06
**Upgrade:** Go 1.24.6 → Go 1.25.5
**Status:** ✅ **COMPLETE** - All Tests Passing (5636/5636)

---

## Executive Summary

### What Was Done

| Category | Result |
|----------|--------|
| **Code Changes** | 4 files (3 nil-pointer bugs, 1 test update) |
| **Config Changes** | go.mod, .go-version, Dockerfile, CI workflows |
| **Tests Passing** | ✅ 5636/5636 (100%) |
| **CI Status** | ✅ Go 1.25.x passing |
| **Production Impact** | ✅ Minimal |

### Key Findings

1. **Nil-pointer bugs** - Go 1.25 compiler fix exposed 3 critical bugs
2. **TLS alert changes** - Go 1.25 changed alert codes in standard TLS path
3. **Dual TLS modes** - Tyk supports both standard and custom verification (different behavior)

### Outstanding Items

- [ ] Wait for `tykio/golang-cross:1.25-bullseye` Docker image
- [ ] Update plugin compiler workflow
- [ ] Update release workflow

---

## Upgrade Process Methodology

This section documents the repeatable process for upgrading Go versions in Tyk.

### Phase 1: Pre-Upgrade Investigation

**Goal:** Understand what changed in the target Go version and identify potential impact.

**Steps:**

1. **Read Release Notes**
   ```bash
   # Review official Go release notes
   open https://go.dev/doc/go1.25
   ```
   - Focus on "Breaking Changes" section
   - Note any "stricter" language (indicates behavior changes)
   - Check for new GODEBUG settings
   - Review compiler changes

2. **Identify Impact Categories**
   - Syntax changes (rare)
   - Compiler behavior changes (common)
   - Standard library changes
   - Runtime changes
   - Security restrictions

3. **Search Codebase for Affected Patterns**
   ```bash
   # Example: Search for nil-pointer-before-error-check pattern
   rg 'v2Config\.' --type go -A 2 -B 2

   # Example: Search for TLS certificate usage
   rg 'RequireAndVerifyClientCert|VerifyPeerCertificate' --type go
   ```

4. **Document Findings**
   - Create UPGRADE.md with initial analysis
   - List all potentially affected code patterns
   - Estimate impact (HIGH/MEDIUM/LOW)

### Phase 2: Create Investigation Branch

**Goal:** Set up isolated environment to test the upgrade.

**Steps:**

1. **Create Branch**
   ```bash
   git checkout -b TT-XXXXX-spike-investigate-impact-of-updating-to-go-X-Y
   ```

2. **Create Jira Subtask**
   ```bash
   # Document the upgrade process
   acli jira workitem create subtask TT-XXXXX \
     --summary "Investigate and document Go X.Y upgrade process"
   ```

3. **Initial Commit - Documentation Only**
   ```bash
   # Create UPGRADE.md with initial findings
   git add UPGRADE.md
   git commit -m "Add initial Go X.Y upgrade analysis"
   ```

### Phase 3: Upgrade Go Version (Test What Breaks)

**Goal:** Upgrade without workarounds to identify actual issues.

**Steps:**

1. **Update go.mod**
   ```bash
   # Update ONLY the version, no GODEBUG changes yet
   sed -i 's/go 1.24.6/go 1.25.5/' go.mod
   go mod tidy
   ```

2. **Update Development Tools**
   ```bash
   # Update .go-version for local development
   echo "1.25" > .go-version

   # Update Dockerfile
   sed -i 's/GO_VERSION=1.24/GO_VERSION=1.25/' Dockerfile
   ```

3. **Run Tests Locally**
   ```bash
   go test ./... -v
   ```
   - Document all failures
   - Note exact error messages
   - Capture file paths and line numbers

4. **Commit Changes**
   ```bash
   git add go.mod go.sum .go-version Dockerfile
   git commit -m "Upgrade to Go X.Y.Z"
   ```

### Phase 4: Fix Identified Issues

**Goal:** Fix code issues exposed by the upgrade.

**Steps:**

1. **Prioritize Fixes**
   - Critical: Compilation errors, panics
   - High: Test failures
   - Medium: Warnings, deprecations
   - Low: Style, performance

2. **Fix Issues One Category at a Time**
   ```bash
   # Example: Fix nil-pointer issues
   # 1. Read the file
   # 2. Identify the bug
   # 3. Apply fix
   # 4. Run affected tests
   # 5. Commit with clear message

   git add <file>
   git commit -m "Fix nil-pointer bug in <component>"
   ```

3. **Document Each Fix**
   - Update UPGRADE.md with:
     - File path and line numbers
     - Problem description
     - Fix applied
     - Testing performed

4. **Update Tests If Needed**
   - Only update tests if Go behavior legitimately changed
   - Never update tests to hide bugs
   - Document why test changes are correct

### Phase 5: Update CI/CD

**Goal:** Ensure all CI pipelines use the new Go version.

**Steps:**

1. **Update GitHub Actions**
   ```bash
   # Update CI matrix
   sed -i 's/go-version: \[1.24.x\]/go-version: [1.25.x]/' \
     .github/workflows/ci-tests.yml
   ```

2. **Identify Docker Image Dependencies**
   ```bash
   # Find all workflows using golang-cross
   grep -r "golang-cross" .github/workflows/
   ```

3. **Document Blockers**
   - If custom Docker images needed, note in UPGRADE.md
   - Create follow-up tickets for infrastructure work

4. **Commit CI Changes**
   ```bash
   git add .github/workflows/
   git commit -m "Update CI to use Go X.Y"
   ```

### Phase 6: Validation

**Goal:** Verify the upgrade is complete and safe.

**Steps:**

1. **Create Pull Request**
   ```bash
   git push -u origin <branch-name>
   gh pr create --title "Upgrade to Go X.Y.Z" \
     --body "See UPGRADE.md for complete analysis"
   ```

2. **Monitor CI Results**
   ```bash
   gh pr checks <PR-number>
   ```
   - Document any new failures
   - Investigate root causes
   - Apply additional fixes if needed

3. **Validate Test Coverage**
   - Confirm all tests pass
   - Check for skipped tests
   - Verify no regressions

4. **Document Final Status**
   - Update UPGRADE.md with results
   - Add CI status
   - List any remaining blockers

---

## Step-by-Step Execution (Go 1.25.5)

This section documents what we actually did for the Go 1.25.5 upgrade.

### Step 1: Pre-Upgrade Investigation

**Action:** Reviewed [Go 1.25 Release Notes](https://go.dev/doc/go1.25)

**Key Findings:**
- SHA-1 signature algorithms disabled in TLS 1.2 (RFC 9155)
- Nil-pointer compiler bug fixed (now panics correctly per Go spec)
- GOMAXPROCS container-aware improvements (non-breaking)

**Codebase Search Results:**
- Found SHA-1 test certificate in `ci/tests/specs/config/certs.js` (uses HTTP, not affected)
- Identified 12 potential nil-pointer patterns (3 critical, 9 false positives)
- Located TLS certificate validation in `gateway/cert.go` (dual-mode implementation)

### Step 2: Create Branch and Documentation

```bash
git checkout -b TT-16341-spike-investigate-impact-of-updating-to-go-1-25
# Created UPGRADE.md with initial analysis
# Created Jira subtask TT-16387
```

### Step 3: Upgrade Go Version

**Changes Made:**
```bash
# go.mod: 1.24.6 → 1.25.5 (without tlssha1=1 initially)
# .go-version: 1.24 → 1.25
# Dockerfile: GO_VERSION=1.24 → GO_VERSION=1.25
go mod tidy
```

**Initial Test Results:**
- ✅ Compilation successful
- ❌ 3 nil-pointer panics discovered (critical bugs)
- ❌ TLS test failures (error message changes)

### Step 4: Fix Nil-Pointer Bugs

**Issue #1:** `apidef/adapter/gqlengineadapter/adapter_proxy_only.go:49-63`
```go
// BEFORE (Bug):
v2Config, err := factory.EngineV2Configuration()
v2Config.EnableSingleFlight(false)  // ❌ PANIC if err != nil
return &v2Config, err

// AFTER (Fixed):
v2Config, err := factory.EngineV2Configuration()
if err != nil {
    return nil, err
}
v2Config.EnableSingleFlight(false)
return &v2Config, nil
```
**Commit:** `3f2404f`

**Issue #2:** `apidef/adapter/gqlengineadapter/enginev3/adapter_proxy_only.go:47-61`
- Same pattern as Issue #1, v3 engine
- **Commit:** `f32c792`

**Issue #3:** `apidef/oas/default.go:287-304`
```go
// BEFORE (Bug):
parsedURL, err := url.Parse(upstreamURL)
if err != nil || !parsedURL.IsAbs() {  // ❌ PANIC if err != nil
    return fmt.Errorf("%w %s", errInvalidServerURL,
        fmt.Sprintf(invalidServerURLFmt, parsedURL))  // ❌ ALSO PANICS
}

// AFTER (Fixed):
parsedURL, err := url.Parse(upstreamURL)
if err != nil {
    // Handle error without accessing parsedURL
    return errInvalidUpstreamURL
}
if !parsedURL.IsAbs() {
    // Safe to use parsedURL here
    return fmt.Errorf("%w %s", errInvalidServerURL,
        fmt.Sprintf(invalidServerURLFmt, parsedURL))
}
```
**Commit:** `38d54b2`

### Step 5: Fix TLS Test Failures

**Root Cause Analysis:**

Researched TLS error message changes:
1. Checked `crypto/tls/alert.go` source code
2. Found Go commit [`fd605450`](https://github.com/golang/go/commit/fd605450) (TLS alert change)
3. Reviewed RFC 5246 §7.4.6 (TLS specification)
4. Analyzed Tyk's `gateway/cert.go` implementation

**Discovery:** Tyk has TWO TLS verification modes:
- **Standard path** (`SkipClientCAAnnouncement=false`): Uses `tls.RequireAndVerifyClientCert`
  - Go 1.25 sends Alert 40 (`handshake_failure`)
- **Custom callback** (`SkipClientCAAnnouncement=true`): Uses custom `VerifyPeerCertificate`
  - Still sends Alert 42 (`bad_certificate`)

**Fix Applied:** `gateway/cert_test.go`
```go
// Dynamic error message based on verification mode
certRequiredErr := "tls: handshake failure" // Go 1.25 standard path
if skipCAAnnounce {
    certRequiredErr = badcertErr // Custom callback path (unchanged)
}
```
**Commits:** `84f9209`, `b2ad9b9`, `99664c1`

### Step 6: Update CI/CD

**Changes Made:**
```bash
# .github/workflows/ci-tests.yml
# go-version: [1.24.x] → go-version: [1.25.x]
```
**Commit:** `39e93ed`

**Blockers Identified:**
- Docker workflows require `tykio/golang-cross:1.25-bullseye` (not yet available)
- Documented in UPGRADE.md as outstanding item

### Step 7: Validation

**Pull Request:** [#7658](https://github.com/TykTechnologies/tyk/pull/7658)

**CI Results:**
- ✅ Go 1.25.x Redis 7: PASS (5636/5636 tests)
- ✅ Unit Tests & Linting: PASS
- ❌ docker-build: Blocked (waiting for Docker image)
- ❌ release workflow: Blocked (waiting for Docker image)

**Final Status:** ✅ Code changes complete, infrastructure work pending

---

## Reusable Upgrade Checklist

Use this checklist for any future Go version upgrade:

### Phase 1: Investigation (1-2 hours)
- [ ] Read official Go release notes
- [ ] Identify breaking changes and GODEBUG settings
- [ ] Search codebase for affected patterns
- [ ] Document findings in UPGRADE.md

### Phase 2: Setup (15 minutes)
- [ ] Create branch: `TT-XXXXX-spike-investigate-impact-of-updating-to-go-X-Y`
- [ ] Create Jira subtask for documentation
- [ ] Commit initial UPGRADE.md

### Phase 3: Upgrade (30 minutes)
- [ ] Update `go.mod` (version only, no GODEBUG yet)
- [ ] Run `go mod tidy`
- [ ] Update `.go-version`, `Dockerfile`
- [ ] Run tests locally, document failures

### Phase 4: Fix Issues (2-4 hours, varies)
- [ ] Fix critical bugs (compilation errors, panics)
- [ ] Fix test failures (verify changes are correct)
- [ ] Update UPGRADE.md with each fix
- [ ] Commit fixes with clear messages

### Phase 5: CI/CD (30 minutes)
- [ ] Update `.github/workflows/*.yml` with new Go version
- [ ] Identify Docker image dependencies
- [ ] Document blockers for infrastructure team

### Phase 6: Validation (1-2 hours)
- [ ] Create PR with all changes
- [ ] Monitor CI results
- [ ] Fix any new failures
- [ ] Document final status in UPGRADE.md

### Phase 7: Documentation (30 minutes)
- [ ] Update UPGRADE.md with complete analysis
- [ ] Add comments to Jira ticket
- [ ] Update PR description
- [ ] Create Confluence page (optional)

**Total Estimated Time:** 6-10 hours (varies by complexity)

---

## Key Learnings

### Investigation Best Practices

1. **Start without workarounds** - Upgrade the version first, see what breaks
2. **Search for actual commits** - Release notes are summaries; find source code changes
3. **Test all code paths** - Tyk's dual TLS modes required testing both configurations
4. **Document as you go** - Update UPGRADE.md with each discovery

### Common Pitfalls

1. **Assuming behavior** - Always verify with actual testing
2. **Incomplete fixes** - Search entire codebase, not just first occurrence
3. **Wrong test updates** - Only update tests if Go behavior legitimately changed
4. **Scope issues** - Understand variable scope in test functions

### Tools Used

```bash
# Code search
rg '<pattern>' --type go -A 2 -B 2

# Git search
git log --all --grep='<keyword>'

# Go source research
open https://github.com/golang/go/commit/<hash>

# CI monitoring
gh pr checks <PR-number>
gh run view <run-id>
```

---

## Appendix: Go 1.25 Specific Details

### Breaking Changes

**1. SHA-1 TLS Restriction**
- SHA-1 signature algorithms disabled in TLS 1.2 per RFC 9155
- Requires `GODEBUG=tlssha1=1` to re-enable
- Impact: Tyk accepts SHA-1 certificates but test uses HTTP (not affected)

**2. Nil-Pointer Compiler Fix**
- Compiler previously delayed nil checks incorrectly
- Now correctly panics per Go spec
- Impact: Exposed 3 critical bugs in Tyk codebase

**3. TLS Alert Code Change**
- Standard `RequireAndVerifyClientCert` path changed
- Alert 42 (`bad_certificate`) → Alert 40 (`handshake_failure`)
- Commit: [`fd605450`](https://github.com/golang/go/commit/fd605450)
- Impact: Tests needed update for standard path only

### Non-Breaking Changes

**1. GOMAXPROCS Container-Aware**
- Now considers CPU bandwidth limits in cgroups
- Positive impact for containerized deployments
- No action required

**2. Other Improvements**
- Stricter certificate parsing (ASN.1/X.509)
- New JSON implementation (compatible)
- DWARF v5 debug info (faster linking)

### Certificate Usage in Tyk

Tyk uses certificates in 6 locations:
- Server TLS (`gateway/cert.go:385`)
- Client mTLS validation (`gateway/cert.go:465,488`)
- Control API TLS (`gateway/server.go:690`)
- Certificate validation middleware (`gateway/mw_certificate_check.go:108`)
- Request signing (`gateway/mw_request_signing.go:137`)
- Upstream mTLS (`gateway/cert.go:581,595`)

**Note:** Tyk uses SHA-256 for certificate fingerprinting (not affected by SHA-1 restrictions)

### Tools for Certificate Checking

```bash
# Check certificate signature algorithm
openssl x509 -in cert.pem -noout -text | grep "Signature Algorithm"

# Check if certificate uses SHA-1
openssl x509 -in cert.pem -noout -text | grep -q sha1 \
  && echo "⚠️ SHA-1 found" || echo "✅ No SHA-1"

# Generate SHA-256 certificate
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 3650 -sha256 \
  -subj "/C=US/O=Tyk/CN=example.com"
```

---

## References

### Go Resources
- [Go 1.25 Release Notes](https://tip.golang.org/doc/go1.25)
- [Go Issue #72006 - BoGo Test Suite](https://github.com/golang/go/issues/72006)
- [Commit fd605450 - TLS Alert Change](https://github.com/golang/go/commit/fd605450)
- [RFC 5246 - TLS 1.2 Specification](https://tools.ietf.org/html/rfc5246)
- [RFC 9155 - SHA-1 Deprecation](https://tools.ietf.org/html/rfc9155)

### Tyk Resources
- **Jira Ticket:** [TT-16341](https://tyktech.atlassian.net/browse/TT-16341)
- **Jira Subtask:** [TT-16387](https://tyktech.atlassian.net/browse/TT-16387)
- **Pull Request:** [#7658](https://github.com/TykTechnologies/tyk/pull/7658)
- **Branch:** `TT-16341-spike-investigate-impact-of-updating-to-go-1-25`

### Key Commits
- `3f2404f` - Fix nil-pointer in GraphQL adapter v2
- `f32c792` - Fix nil-pointer in GraphQL adapter v3
- `38d54b2` - Fix nil-pointer in OAS URL validation
- `84f9209` - Add dual-mode TLS test support
- `b2ad9b9` - Fix TLS test variable scope
- `99664c1` - Fix separate TLS test function
- `39e93ed` - Update CI matrix to Go 1.25.x

---

**Document Version:** 2.0
**Last Updated:** 2026-01-07
**Focus:** Process-oriented upgrade methodology
**Status:** Complete - All Tests Passing ✅
