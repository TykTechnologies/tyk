# Go 1.25.5 Upgrade Guide for Tyk Products

**Audience:** Engineers who have read [Go 1.25 Release Notes](https://go.dev/doc/go1.25)
**Purpose:** Concrete steps to upgrade any Tyk product to Go 1.25.5
**Applies to:** tyk, tyk-pump, tyk-analytics, tyk-identity-broker, tyk-sync, etc.

---

## Release Notes Summary

**Breaking Changes:**
1. SHA-1 signature algorithms disabled in TLS 1.2
2. Nil-pointer compiler bug fixed (now panics correctly)
3. TLS alert codes changed (undocumented)

**Non-Breaking:**
4. GOMAXPROCS container-aware on Linux

---

## Step 1: Update go.mod

**Command:**
```bash
# Update Go version
sed -i 's/go 1\.24\.[0-9]/go 1.25.5/' go.mod

# Regenerate go.sum
go mod tidy
```

**Verify:**
```bash
grep "^go " go.mod
# Expected: go 1.25.5
```

**Note on GODEBUG:**
- Do NOT add `tlssha1=1` unless you have confirmed SHA-1 certificate usage in production
- Test without it first to see what breaks

**Commit:**
```bash
git add go.mod go.sum
git commit -m "Update go.mod to Go 1.25.5"
```

---

## Step 2: Update Development Tools

### Update .go-version (if exists)

```bash
# Check if file exists
if [ -f .go-version ]; then
    echo "1.25" > .go-version
    git add .go-version
fi
```

### Update Dockerfile (if exists)

```bash
# Find and update GO_VERSION
if [ -f Dockerfile ]; then
    sed -i 's/GO_VERSION=1\.24/GO_VERSION=1.25/' Dockerfile
    git add Dockerfile
fi

# Check for other Dockerfiles
find . -name "Dockerfile*" -exec sed -i 's/GO_VERSION=1\.24/GO_VERSION=1.25/' {} \;
```

**Commit:**
```bash
git commit -m "Update .go-version and Dockerfile to Go 1.25"
```

---

## Step 3: Identify and Update CI Files

### Find all CI workflow files

```bash
# List all GitHub Actions workflows
find .github/workflows -name "*.yml" -o -name "*.yaml"
```

### Update Go version in CI

```bash
# Update go-version matrix
find .github/workflows -name "*.yml" -exec \
  sed -i 's/go-version: \[1\.24\.x\]/go-version: [1.25.x]/' {} \;

# Alternative: go-version without brackets
find .github/workflows -name "*.yml" -exec \
  sed -i 's/go-version: 1\.24\.x/go-version: 1.25.x/' {} \;

# Alternative: setup-go with specific version
find .github/workflows -name "*.yml" -exec \
  sed -i 's/go-version: "1\.24"/go-version: "1.25"/' {} \;
```

### Manual verification

**Check each workflow file for:**
```yaml
# Pattern 1: Matrix strategy
strategy:
  matrix:
    go-version: [1.25.x]  # ✅ Updated

# Pattern 2: Direct version
- uses: actions/setup-go@v5
  with:
    go-version: 1.25.x  # ✅ Updated

# Pattern 3: go-version-file (no change needed)
- uses: actions/setup-go@v5
  with:
    go-version-file: go.mod  # ✅ Reads from go.mod automatically
```

**Commit:**
```bash
git add .github/workflows/
git commit -m "Update CI workflows to use Go 1.25.x"
```

---

## Step 4: Identify Nil-Pointer Bugs

### Search Pattern

**What to look for:**
```go
// PATTERN: Using return value before checking error
result, err := function()
result.Method()      // ❌ BAD: Uses result before checking err
if err != nil {
    return err
}
```

### Search Command

```bash
# Search for potential nil-pointer bugs
rg 'v[a-zA-Z0-9_]+, err :=' --type go -A 3 | \
  grep -B 1 'if err' | \
  grep -v 'if err' | \
  grep '\.'
```

**This finds:**
- Lines with `variable, err :=` assignment
- Followed by usage of `variable.Something()`
- Before `if err != nil` check

### Manual Review

For each match, check if:
1. The variable is used (method call or field access) **before** the error check
2. If yes, it's a bug that needs fixing

### Example Bugs Found in tyk-gateway

**Pattern 1: Method call before error check**
```go
// ❌ BAD
v2Config, err := factory.EngineV2Configuration()
v2Config.EnableSingleFlight(false)  // Panics if err != nil
return &v2Config, err

// ✅ GOOD
v2Config, err := factory.EngineV2Configuration()
if err != nil {
    return nil, err
}
v2Config.EnableSingleFlight(false)
return &v2Config, nil
```

**Pattern 2: Compound if statement**
```go
// ❌ BAD
parsedURL, err := url.Parse(urlString)
if err != nil || !parsedURL.IsAbs() {  // Accesses parsedURL when err != nil
    return fmt.Errorf("invalid: %s", parsedURL)
}

// ✅ GOOD
parsedURL, err := url.Parse(urlString)
if err != nil {
    return fmt.Errorf("invalid: %s", urlString)  // Use original string
}
if !parsedURL.IsAbs() {
    return fmt.Errorf("invalid: %s", parsedURL)  // Safe to use parsedURL
}
```

### Fix Each Bug

```bash
# For each file with bugs:
# 1. Read the file to understand context
# 2. Apply the fix (add error check before using value)
# 3. Run tests for that package
# 4. Commit with clear message

git add <file>
git commit -m "Fix nil-pointer bug in <component>

Go 1.25 compiler fix exposes bug where value is used before
checking error. This would cause panic if error occurs.

File: <file>:<line>
Pattern: Used result.Method() before 'if err != nil' check"
```

---

## Step 5: Run Tests and Fix TLS Failures

### Run full test suite

```bash
# Run all tests
go test ./... -v

# Look for TLS-related failures
go test ./... -v 2>&1 | grep -i "tls:"
```

### Expected TLS Failures

**Error Pattern:**
```
FAIL: TestSomeTLS
  file_test.go:123: Expect error 'remote error: tls: handshake failure'
                     to contain 'tls: bad certificate'
```

**Why This Happens:**

Go 1.25 changed TLS alert codes for client certificate validation:
- **Go 1.24:** Alert 42 `"tls: bad certificate"`
- **Go 1.25:** Alert 40 `"tls: handshake failure"` (RFC 5246 compliant)

**When to update tests:**

Only update if your code uses **standard TLS verification**:
```go
tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
tlsConfig.ClientCAs = certPool
```

**When NOT to update:**

If your code uses **custom verification callback**:
```go
tlsConfig.ClientAuth = tls.RequestClientCert
tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    // Custom validation
}
```
This path still sends Alert 42 (`bad certificate`).

### Fix TLS Tests

**If using standard verification:**
```bash
# Find test files expecting "tls: bad certificate"
rg '"tls: bad certificate"' --type go

# Update to expect "tls: handshake failure" instead
sed -i 's/"tls: bad certificate"/"tls: handshake failure"/g' <test_file>
```

**If supporting both modes (like tyk-gateway):**
```go
// Dynamic error based on configuration
certRequiredErr := "tls: handshake failure"  // Standard mode (Go 1.25)
if usingCustomCallback {
    certRequiredErr = "tls: bad certificate"  // Custom callback (unchanged)
}

// Use in test assertion
assert.ErrorContains(t, err, certRequiredErr)
```

**Commit:**
```bash
git add <test_files>
git commit -m "Update TLS tests for Go 1.25 alert behavior

Go 1.25 changed TLS alert codes (commit fd605450) for standard
RequireAndVerifyClientCert to send Alert 40 (handshake_failure)
instead of Alert 42 (bad_certificate) per RFC 5246 §7.4.6.

Tests updated to expect correct Go 1.25 behavior."
```

---

## Step 6: Check for SHA-1 Certificate Usage

### Search for certificate handling

```bash
# Find TLS configuration
rg 'tls\.Config|x509\.Certificate' --type go

# Find certificate loading
rg 'LoadX509KeyPair|ParseCertificate|CertPool' --type go

# Find HTTPS clients/servers
rg 'http\.Client|http\.Server.*TLS' --type go
```

### Check test certificates

```bash
# Find certificate files in tests
find . -name "*.pem" -o -name "*.crt" -o -name "*.cert"

# Check if they use SHA-1
for cert in $(find . -name "*.pem"); do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -noout -text 2>/dev/null | grep "Signature Algorithm" || echo "Not a certificate"
done
```

### Decision on GODEBUG

**If SHA-1 certificates found in production code:**
```bash
# Add to go.mod
cat >> go.mod <<EOF

godebug (
    tlssha1=1  // Allow SHA-1 certificates in TLS 1.2
)
EOF
```

**If only in tests (using HTTP or HTTPS with skip verify):**
- No GODEBUG needed
- Consider regenerating test certs with SHA-256

**Regenerate test certificate (optional):**
```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test.key -out test.pem -days 3650 -sha256 \
  -subj "/C=US/O=Test/CN=test.local"
```

---

## Step 7: Check Docker Image Dependencies

### Identify Docker build workflows

```bash
# Find workflows that build Docker images
rg 'docker.*build|golang-cross' .github/workflows/
```

### Common blockers

**Pattern 1: Custom golang-cross image**
```yaml
# ❌ Will fail - image not updated yet
image: tykio/golang-cross:1.24-bullseye

# ⏳ Wait for image to be published
image: tykio/golang-cross:1.25-bullseye
```

**Pattern 2: Official Go image**
```yaml
# ✅ Works - official image available
image: golang:1.25-bullseye
```

### Document blockers

```bash
# Create note for infrastructure team
cat > DOCKER_BLOCKERS.md <<EOF
# Docker Image Blockers

The following CI jobs are blocked waiting for Docker images:

1. Job: <workflow-name>
   Image needed: tykio/golang-cross:1.25-bullseye
   Status: Not yet published

Action: Contact DevOps team to publish Go 1.25 image
EOF
```

---

## Step 8: Validate Locally

### Build the project

```bash
# Clean build
go clean -cache
go build ./...
```

### Run full test suite

```bash
# All tests
go test ./... -v -race -coverprofile=coverage.out

# Check coverage
go tool cover -func=coverage.out | tail -1
```

### Run specific tests for changed areas

```bash
# If fixed nil-pointer bugs
go test ./path/to/affected/package -v

# If updated TLS tests
go test ./... -v -run TLS
```

### Verify no regressions

```bash
# Compare test results
# Before: go test ./... > before.log 2>&1
# After:  go test ./... > after.log 2>&1
# diff before.log after.log
```

---

## Step 9: Create Pull Request

### Push changes

```bash
git push -u origin <branch-name>
```

### Create PR

```bash
gh pr create \
  --title "Upgrade to Go 1.25.5" \
  --body "## Summary

Upgrades Go version from 1.24.x to 1.25.5.

## Changes

- Updated go.mod to Go 1.25.5
- Fixed X nil-pointer bugs exposed by compiler fix
- Updated TLS tests for Go 1.25 alert behavior
- Updated CI workflows to use Go 1.25.x

## Testing

- ✅ All tests passing locally (XXXX/XXXX)
- ✅ No regressions detected
- ⏳ CI checks running

## Breaking Changes

None. All changes are bug fixes required by Go 1.25.

## Notes

See UPGRADE.md for detailed process documentation.
See UPGRADE2.md for specific findings and rationale."
```

### Monitor CI

```bash
# Watch CI checks
gh pr checks <PR-number> --watch

# View specific job
gh run view <run-id>
```

---

## Validation Checklist

Use this checklist to ensure complete upgrade:

### Version Updates
- [ ] go.mod updated to 1.25.5
- [ ] go.sum regenerated
- [ ] .go-version updated (if exists)
- [ ] Dockerfile(s) updated (if exist)
- [ ] All CI workflow files updated

### Code Changes
- [ ] Searched for nil-pointer-before-error-check pattern
- [ ] Fixed all identified bugs
- [ ] Added error checks before using return values
- [ ] Committed each fix with clear message

### Testing
- [ ] All tests pass locally
- [ ] TLS tests updated if needed
- [ ] No regressions detected
- [ ] Coverage maintained or improved

### TLS Verification
- [ ] Identified TLS verification mode (standard vs custom)
- [ ] Updated test assertions correctly
- [ ] Documented why changes are correct

### Certificate Handling
- [ ] Checked for SHA-1 certificate usage
- [ ] Decided on GODEBUG (if needed)
- [ ] Documented decision

### CI/CD
- [ ] All workflow files updated
- [ ] Docker image dependencies identified
- [ ] Blockers documented for DevOps

### Documentation
- [ ] Pull request created with clear description
- [ ] Changes documented
- [ ] Rationale provided for each change

---

## Common Issues and Solutions

### Issue 1: Tests fail with "panic: runtime error: invalid memory address"

**Cause:** Nil-pointer bug exposed by Go 1.25 compiler fix

**Solution:**
1. Look at stack trace to find which value is nil
2. Find the error check: `if err != nil`
3. Move usage of return value AFTER the error check

### Issue 2: TLS tests fail with error message mismatch

**Cause:** Go 1.25 changed TLS alert codes

**Solution:**
1. Determine if using standard or custom verification
2. Update test to expect correct error for that mode
3. Document why the change is correct (not hiding a bug)

### Issue 3: Docker build fails with "go.mod requires go >= 1.25.5"

**Cause:** CI using old Go 1.24 Docker image

**Solution:**
1. Update workflow to use Go 1.25 image
2. If custom image not available, use official golang:1.25
3. Document blocker if custom image needed

### Issue 4: "GODEBUG: unknown setting tlssha1"

**Cause:** Typo or wrong format in go.mod

**Solution:**
```go
// ✅ CORRECT format
godebug (
    tlssha1=1
)

// ❌ WRONG - not in godebug block
tlssha1=1
```

---

## Time Estimates

| Task | Estimated Time |
|------|----------------|
| Update go.mod and config files | 15 minutes |
| Search and fix nil-pointer bugs | 1-3 hours (depends on findings) |
| Fix TLS tests | 30 minutes - 2 hours |
| Update CI workflows | 30 minutes |
| Local testing and validation | 1 hour |
| PR creation and documentation | 30 minutes |
| **Total** | **4-8 hours** |

---

## Quick Reference Commands

```bash
# Update all version files
sed -i 's/go 1\.24\.[0-9]/go 1.25.5/' go.mod && go mod tidy
echo "1.25" > .go-version
find . -name "Dockerfile*" -exec sed -i 's/GO_VERSION=1\.24/GO_VERSION=1.25/' {} \;
find .github/workflows -name "*.yml" -exec sed -i 's/go-version: \[1\.24\.x\]/go-version: [1.25.x]/' {} \;

# Search for nil-pointer bugs
rg 'v[a-zA-Z0-9_]+, err :=' --type go -A 3 | grep -B 1 'if err' | grep -v 'if err' | grep '\.'

# Search for TLS test failures
go test ./... -v 2>&1 | grep -i "tls:"

# Check certificate signature algorithms
find . -name "*.pem" -exec sh -c 'echo "=== {} ===" && openssl x509 -in "{}" -noout -text 2>/dev/null | grep "Signature Algorithm"' \;

# Run tests
go test ./... -v -race

# Create PR
git push && gh pr create --title "Upgrade to Go 1.25.5" --body "See UPGRADE2.md"
```

---

**Document Version:** 2.0
**Last Updated:** 2026-01-07
**Applies to:** All Tyk products
**Status:** Production ready
