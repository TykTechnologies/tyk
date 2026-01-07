# Upgrade to go 1.25.5 analysis

Go 1.25.5 introduces several important changes that may affect Tyk projects. This analysis documents all potentially breaking changes discovered during the Tyk Gateway upgrade and provides concrete steps to upgrade any Tyk project.

This document contains detailed analysis of what breaks and why, along with concrete steps to perform the upgrade and validate your changes.

## Potentially Breaking Changes

### 1. SHA-1 Certificates Disabled in TLS 1.2

**Release Notes:** [crypto/tls - SHA-1 disabled](https://tip.golang.org/doc/go1.25#crypto/tls)

**What Changed:**
- Go 1.25 disallows SHA-1 signature algorithms in TLS 1.2 handshakes per RFC 9155
- TLS connections using SHA-1 certificates will fail with handshake errors

**Impact:**
- **HIGH** if your application uses SHA-1 certificates for HTTPS connections
- **HIGH** if clients connect to your server with SHA-1 certificates
- **NONE** if using SHA-256 or better signature algorithms
- **NONE** if certificates only used for fingerprinting/identification (not TLS handshakes)

**When It Breaks:**
```go
// This will fail if certificate uses SHA-1 signature
cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
server := &http.Server{
    TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
}
server.ListenAndServeTLS("", "") // ❌ Handshake fails
```

**Workaround:**
```
# Add to go.mod after the go version line
godebug (
    tlssha1=1
)
```

**Permanent Fix:**
- Regenerate certificates with SHA-256 or better
- Update certificate authority

---

### 2. Nil-Pointer Compiler Bug Fixed

**Release Notes:** [Compiler - Nil check ordering](https://tip.golang.org/doc/go1.25#compiler)

**What Changed:**
- Go 1.24 compiler incorrectly allowed using return values before checking errors
- Go 1.25 correctly enforces nil checks per Go specification
- Programs that worked incorrectly will now panic as they should have always done

**Impact:**
- **HIGH** - Existing bugs will be exposed and cause panics
- These are **real bugs** that should have panicked but didn't due to compiler bug

**When It Breaks:**
```go
// This code has always been wrong, but Go 1.24 allowed it
result, err := DoSomething()
value := result.Field    // ❌ Go 1.25: PANIC if err != nil
if err != nil {
    return err
}
```

**Why This Is Breaking:**
- Not a regression - this is a bug fix
- Code that "worked" in Go 1.24 was violating Go spec
- Go 1.25 correctly panics on nil dereference

**Fix:**
```go
result, err := DoSomething()
if err != nil {
    return err
}
value := result.Field    // ✅ Safe: error checked first
```

---

### 3. TLS Alert Codes Changed

**Release Notes:** [crypto/tls - Stricter compliance](https://tip.golang.org/doc/go1.25#crypto/tls) | [Go commit fd605450](https://github.com/golang/go/commit/fd605450)

**What Changed:**
- Go 1.25 changed TLS alert selection for client certificate validation failures
- Standard verification path now sends Alert 40 (`handshake_failure`) instead of Alert 42 (`bad_certificate`)
- Change implements RFC 5246 §7.4.6 correctly

**Impact:**
- **MEDIUM** - Only affects code that validates TLS error message strings
- **NONE** to application logic - both alerts indicate certificate validation failure
- This change caused gateway mTLS tests to fail (tests were checking exact error messages)
- Most applications won't be affected unless they validate specific TLS error text

**When It Breaks:**
```go
// Test code checking exact error message
err := client.Get("https://example.com")
if !strings.Contains(err.Error(), "tls: bad certificate") { // ❌ Fails in Go 1.25
    t.Error("Expected bad certificate error")
}
```

**What Changed:**
```go
// Go 1.24
tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
// Sends: Alert 42 "tls: bad certificate"

// Go 1.25
tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
// Sends: Alert 40 "tls: handshake failure"
```

**When NOT Changed:**
```go
// Custom verification still sends Alert 42 (unchanged)
tlsConfig.ClientAuth = tls.RequestClientCert
tlsConfig.VerifyPeerCertificate = func(...) error {
    // Custom validation
}
// Still sends: Alert 42 "tls: bad certificate"
```

**Fix:**
```go
// Update test to expect new error
if !strings.Contains(err.Error(), "tls: handshake failure") { // ✅ Go 1.25
    t.Error("Expected handshake failure")
}
```

---

## Step 1: Update go.mod

```bash
sed -i 's/go 1\.24\.[0-9]/go 1.25.5/' go.mod
go mod tidy
git add go.mod go.sum
git commit -m "Update to Go 1.25.5"
```

---

## Step 2: Update .go-version

```bash
[ -f .go-version ] && echo "1.25" > .go-version && git add .go-version
git commit -m "Update .go-version to 1.25"
```

---

## Step 3: Update Dockerfile

```bash
find . -name "Dockerfile*" -exec sed -i 's/GO_VERSION=1\.24/GO_VERSION=1.25/g' {} \;
git add Dockerfile*
git commit -m "Update Dockerfile to Go 1.25"
```

---

## Step 4: Update CI Files

```bash
find .github/workflows -name "*.yml" -exec sed -i \
  -e 's/go-version: \[1\.24\.x\]/go-version: [1.25.x]/g' \
  -e 's/go-version: 1\.24\.x/go-version: 1.25.x/g' \
  -e 's/go-version: "1\.24"/go-version: "1.25"/g' \
  {} \;

git add .github/workflows/
git commit -m "Update CI workflows to Go 1.25.x"
```

---

## Step 5: Identify and Fix Nil-Pointer Bugs

**Pattern to find:**
```go
result, err := function()
result.Method()  // ❌ Panics if err != nil
if err != nil {
    return err
}
```

**Fix:**
```go
result, err := function()
if err != nil {
    return err
}
result.Method()  // ✅ Safe
```

**Action:**
- Manually review code for this pattern
- Add error checks before using return values
- Commit each fix separately

---

## Step 6: Run Tests

```bash
go test ./... -v
```

---

## Step 7: Fix TLS Test Failures

**If tests fail with:**
```
expected: "tls: bad certificate"
got: "tls: handshake failure"
```

**And code uses standard verification:**
```go
tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
```

**Then update test:**
```bash
# Change test expectation
sed -i 's/"tls: bad certificate"/"tls: handshake failure"/g' <test_file>
git add <test_file>
git commit -m "Update TLS test for Go 1.25 alert behavior"
```

**Note:** Custom verification callbacks (`VerifyPeerCertificate`) unchanged.

---

## Step 8: Check SHA-1 Certificates

**If production uses SHA-1 certificates in TLS:**

```bash
# Add to go.mod after the go version line
cat >> go.mod <<'EOF'
godebug (
    tlssha1=1
)
EOF

git add go.mod
git commit -m "Add tlssha1=1 GODEBUG for SHA-1 certificate support"
```

**Otherwise:** No action needed.

---

## Step 9: Validate

```bash
go build ./...
go test ./... -v -race
git push
```

---

## Quick Commands

```bash
# All updates in one go
sed -i 's/go 1\.24\.[0-9]/go 1.25.5/' go.mod && \
go mod tidy && \
[ -f .go-version ] && echo "1.25" > .go-version && \
find . -name "Dockerfile*" -exec sed -i 's/GO_VERSION=1\.24/GO_VERSION=1.25/g' {} \; && \
find .github/workflows -name "*.yml" -exec sed -i \
  -e 's/go-version: \[1\.24\.x\]/go-version: [1.25.x]/g' \
  -e 's/go-version: 1\.24\.x/go-version: 1.25.x/g' \
  -e 's/go-version: "1\.24"/go-version: "1.25"/g' \
  {} \; && \
git add -A && \
git commit -m "Upgrade to Go 1.25.5"
```

---

## Validation Checklist

- [ ] go.mod updated to 1.25.5
- [ ] .go-version updated (if exists)
- [ ] Dockerfile(s) updated
- [ ] CI workflow files updated
- [ ] Nil-pointer bugs fixed
- [ ] TLS tests updated (if needed)
- [ ] All tests passing
- [ ] Changes committed and pushed

---

**Last Updated:** 2026-01-07
