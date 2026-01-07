# Go 1.25.5 Upgrade Guide

**Prerequisite:** Read [Go 1.25 Release Notes](https://go.dev/doc/go1.25)
**Applies to:** Any Go project

---

## Breaking Changes Summary

1. **SHA-1 TLS disabled** - Requires `GODEBUG=tlssha1=1` to re-enable
2. **Nil-pointer compiler fix** - Code using values before error checks will panic
3. **TLS alert codes changed** - Standard verification sends different error messages

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
# Add to go.mod
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
