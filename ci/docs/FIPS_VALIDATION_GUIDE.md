# FIPS 140-3 Validation Guide

This guide covers how to verify that Tyk Gateway EE and FIPS Docker images
and packages contain properly built FIPS 140-3 compliant binaries.

## Overview

Starting with Go 1.24, FIPS 140-3 is built natively into the Go standard
library via the `GOFIPS140` build setting. Our FIPS builds use
`GOFIPS140=v1.0.0` which embeds the Go Cryptographic Module v1.0.0
(CAVP Certificate A6650) into the binary and enables FIPS mode by default.

### Key differentiators between binary variants

| Indicator | FIPS | EE | OSS (std) |
|-----------|------|----|----|
| `GOFIPS140` build setting | `v1.0.0-<hash>` | not set | not set |
| Build tags | `goplugin,ee,fips,fips140v1.0` | `goplugin,ee` | `goplugin` |
| `DefaultGODEBUG` includes `fips140=on` | Yes | No | No |
| Binary size | ~105KB larger | baseline | baseline |

> **Note:** `go tool nm | grep fips140` shows symbols in ALL Go 1.25+ binaries
> because the fips140 module is part of the standard library. Symbol count
> alone is NOT a reliable FIPS indicator. Use `go version -m` instead.

---

## 1. Validating Docker Images

### 1.1 Check image architectures

EE and FIPS images: amd64, arm64 only (no s390x).
OSS images: amd64, arm64, s390x.

```bash
# EE image — expect amd64, arm64
docker manifest inspect tykio/tyk-gateway-ee:<tag> | \
  jq '[.manifests[] | select(.platform.os=="linux") | .platform.architecture]'

# FIPS image — expect amd64, arm64
docker manifest inspect tykio/tyk-gateway-fips:<tag> | \
  jq '[.manifests[] | select(.platform.os=="linux") | .platform.architecture]'

# OSS image — expect amd64, arm64, s390x
docker manifest inspect tykio/tyk-gateway:<tag> | \
  jq '[.manifests[] | select(.platform.os=="linux") | .platform.architecture]'
```

### 1.2 Verify base image is hardened (EE and FIPS)

EE and FIPS images use `tykio/dhi-busybox:1.37-fips` as the base.
Compare the first layer digest against the base image:

```bash
TAG=v5.13.0-alphafips4  # change to your tag

for img in tykio/tyk-gateway-ee tykio/tyk-gateway-fips tykio/tyk-gateway; do
  DIGEST=$(docker manifest inspect $img:$TAG 2>/dev/null | \
    jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest')
  LAYER=$(docker buildx imagetools inspect $img:$TAG@$DIGEST --raw 2>/dev/null | \
    jq -r '.layers[0].digest')
  echo "$img: $LAYER"
done

# Compare against the base image
BASE_DIGEST=$(docker manifest inspect tykio/dhi-busybox:1.37-fips 2>/dev/null | \
  jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest')
BASE_LAYER=$(docker buildx imagetools inspect tykio/dhi-busybox:1.37-fips@$BASE_DIGEST --raw 2>/dev/null | \
  jq -r '.layers[0].digest')
echo "base (dhi-busybox): $BASE_LAYER"
```

**Expected:** EE and FIPS first layer match the base. OSS is different.

---

## 2. Validating Binaries

### 2.1 Extract binaries from Docker images

If Docker is available:

```bash
for img in tykio/tyk-gateway-ee tykio/tyk-gateway-fips tykio/tyk-gateway; do
  name=$(echo $img | sed 's/.*\///')
  docker create --name check-$name $img:<tag>
  docker cp check-$name:/opt/tyk-gateway/tyk ./tyk-$name
  docker rm check-$name
done
```

If Docker daemon is not available, use `crane`:

```bash
# brew install crane  (if not installed)
for img in tykio/tyk-gateway-ee tykio/tyk-gateway-fips tykio/tyk-gateway; do
  name=$(echo $img | sed 's/.*\///')
  mkdir -p $name
  crane export --platform linux/amd64 $img:<tag> - | tar xf - -C $name opt/tyk-gateway/tyk
done
```

### 2.2 Check GOFIPS140 build setting (PRIMARY CHECK)

This is the most important validation. A FIPS-compliant binary MUST
have `GOFIPS140` set in its build info.

```bash
go version -m ./tyk-tyk-gateway-fips | grep "GOFIPS140"
```

**Expected output:**

```
build	GOFIPS140=v1.0.0-c2097c7c
```

The hash suffix (`-c2097c7c`) is the Go Cryptographic Module commit.
The key part is `v1.0.0`.

For EE and OSS binaries, `GOFIPS140` should NOT appear:

```bash
go version -m ./tyk-tyk-gateway-ee | grep "GOFIPS140"    # should return nothing
go version -m ./tyk-tyk-gateway | grep "GOFIPS140"       # should return nothing
```

### 2.3 Check build tags

```bash
go version -m ./tyk-tyk-gateway-fips | grep "\-tags="
```

**Expected:**

```
build	-tags=goplugin,ee,fips,fips140v1.0
```

The `fips140v1.0` tag is automatically added by Go when `GOFIPS140` is set.

Comparison:

| Binary | Expected tags |
|--------|--------------|
| FIPS | `-tags=goplugin,ee,fips,fips140v1.0` |
| EE | `-tags=goplugin,ee` |
| OSS | `-tags=goplugin` |

### 2.4 Check DefaultGODEBUG for fips140=on

FIPS binaries have `fips140=on` baked into their default GODEBUG settings,
meaning FIPS mode is enabled automatically at startup without needing
environment variables.

```bash
go version -m ./tyk-tyk-gateway-fips | grep "DefaultGODEBUG"
```

**Expected:** The output includes `fips140=on`:

```
build	DefaultGODEBUG=fips140=on,tls10server=1,...
```

For EE and OSS, `fips140=on` should NOT appear in DefaultGODEBUG:

```bash
go version -m ./tyk-tyk-gateway-ee | grep "DefaultGODEBUG"
# Should NOT contain fips140=on
```

### 2.5 Runtime FIPS validation (requires Docker)

```bash
# FIPS binary with FIPS mode — should start normally
docker run --rm tykio/tyk-gateway-fips:<tag> --version

# Explicitly enforce FIPS-only mode (Go 1.25+)
# This panics if any non-FIPS algorithm is used
docker run --rm -e GODEBUG=fips140=only \
  tykio/tyk-gateway-fips:<tag> --version

# Verify non-FIPS binary rejects FIPS-only mode
# This should fail or show no FIPS enforcement
docker run --rm -e GODEBUG=fips140=on \
  tykio/tyk-gateway:<tag> --version
```

---

## 3. Validating DEB/RPM Packages

### 3.1 Extract and inspect

```bash
# DEB
mkdir -p /tmp/fips-deb
dpkg-deb -x tyk-gateway-fips_*.deb /tmp/fips-deb
go version -m /tmp/fips-deb/opt/tyk-gateway/tyk | grep -E "GOFIPS140|tags|DefaultGODEBUG"

# RPM
mkdir -p /tmp/fips-rpm
rpm2cpio tyk-gateway-fips-*.rpm | (cd /tmp/fips-rpm && cpio -idmv)
go version -m /tmp/fips-rpm/opt/tyk-gateway/tyk | grep -E "GOFIPS140|tags|DefaultGODEBUG"
```

### 3.2 Verify s390x packages exist

FIPS and EE packages should be built for all three architectures.
Docker images are amd64/arm64 only.

```bash
# FIPS packages — all three archs
ls tyk-gateway-fips_*_amd64.deb    # should exist
ls tyk-gateway-fips_*_arm64.deb    # should exist
ls tyk-gateway-fips_*_s390x.deb    # should exist

# EE packages — all three archs
ls tyk-gateway-ee_*_amd64.deb      # should exist
ls tyk-gateway-ee_*_arm64.deb      # should exist (aarch64 for rpm)
ls tyk-gateway-ee_*_s390x.deb      # should exist
```

---

## 4. One-liner full validation script

```bash
#!/bin/bash
TAG=${1:?Usage: $0 <tag>}
PASS=0; FAIL=0

check() {
  if [ "$1" = "true" ]; then
    echo "  PASS: $2"; ((PASS++))
  else
    echo "  FAIL: $2"; ((FAIL++))
  fi
}

echo "Validating tag: $TAG"
echo

# Architecture checks
echo "=== Docker Architectures ==="
EE_ARCHS=$(docker manifest inspect tykio/tyk-gateway-ee:$TAG 2>/dev/null | jq -r '[.manifests[] | select(.platform.os=="linux") | .platform.architecture] | sort | join(",")')
FIPS_ARCHS=$(docker manifest inspect tykio/tyk-gateway-fips:$TAG 2>/dev/null | jq -r '[.manifests[] | select(.platform.os=="linux") | .platform.architecture] | sort | join(",")')
STD_ARCHS=$(docker manifest inspect tykio/tyk-gateway:$TAG 2>/dev/null | jq -r '[.manifests[] | select(.platform.os=="linux") | .platform.architecture] | sort | join(",")')

check "$([ "$EE_ARCHS" = "amd64,arm64" ] && echo true)" "EE archs: $EE_ARCHS (expect amd64,arm64)"
check "$([ "$FIPS_ARCHS" = "amd64,arm64" ] && echo true)" "FIPS archs: $FIPS_ARCHS (expect amd64,arm64)"
check "$([ "$STD_ARCHS" = "amd64,arm64,s390x" ] && echo true)" "STD archs: $STD_ARCHS (expect amd64,arm64,s390x)"

# Base image checks
echo
echo "=== Base Image ==="
get_first_layer() {
  local img=$1
  local digest=$(docker manifest inspect $img 2>/dev/null | jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest')
  docker buildx imagetools inspect $img@$digest --raw 2>/dev/null | jq -r '.layers[0].digest'
}

EE_LAYER=$(get_first_layer "tykio/tyk-gateway-ee:$TAG")
FIPS_LAYER=$(get_first_layer "tykio/tyk-gateway-fips:$TAG")
STD_LAYER=$(get_first_layer "tykio/tyk-gateway:$TAG")
BASE_LAYER=$(get_first_layer "tykio/dhi-busybox:1.37-fips")

check "$([ "$EE_LAYER" = "$BASE_LAYER" ] && echo true)" "EE base matches hardened image"
check "$([ "$FIPS_LAYER" = "$BASE_LAYER" ] && echo true)" "FIPS base matches hardened image"
check "$([ "$STD_LAYER" != "$BASE_LAYER" ] && echo true)" "OSS uses different (distroless) base"

# Binary checks (requires crane: brew install crane)
echo
echo "=== Binary Build Info ==="
TMPDIR=$(mktemp -d)
for variant in ee fips std; do
  case $variant in
    ee)   img="tykio/tyk-gateway-ee:$TAG" ;;
    fips) img="tykio/tyk-gateway-fips:$TAG" ;;
    std)  img="tykio/tyk-gateway:$TAG" ;;
  esac
  mkdir -p $TMPDIR/$variant
  crane export --platform linux/amd64 $img - 2>/dev/null | tar xf - -C $TMPDIR/$variant opt/tyk-gateway/tyk 2>/dev/null
done

FIPS_INFO=$(go version -m $TMPDIR/fips/opt/tyk-gateway/tyk 2>&1)
EE_INFO=$(go version -m $TMPDIR/ee/opt/tyk-gateway/tyk 2>&1)
STD_INFO=$(go version -m $TMPDIR/std/opt/tyk-gateway/tyk 2>&1)

check "$(echo "$FIPS_INFO" | grep -q 'GOFIPS140=v1.0.0' && echo true)" "FIPS binary has GOFIPS140=v1.0.0"
check "$(echo "$EE_INFO" | grep -q 'GOFIPS140' && echo false || echo true)" "EE binary does NOT have GOFIPS140"
check "$(echo "$STD_INFO" | grep -q 'GOFIPS140' && echo false || echo true)" "STD binary does NOT have GOFIPS140"

check "$(echo "$FIPS_INFO" | grep -q 'tags=goplugin,ee,fips' && echo true)" "FIPS binary tags include fips"
check "$(echo "$EE_INFO" | grep -q 'tags=goplugin,ee' && echo true)" "EE binary tags include ee"
check "$(echo "$STD_INFO" | grep -q 'tags=goplugin' && echo true)" "STD binary tags include goplugin"

check "$(echo "$FIPS_INFO" | grep 'DefaultGODEBUG' | grep -q 'fips140=on' && echo true)" "FIPS binary DefaultGODEBUG has fips140=on"
check "$(echo "$EE_INFO" | grep 'DefaultGODEBUG' | grep -q 'fips140=on' && echo false || echo true)" "EE binary DefaultGODEBUG does NOT have fips140=on"

rm -rf $TMPDIR

echo
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
```

Usage:

```bash
chmod +x validate-fips.sh
./validate-fips.sh v5.13.0-alphafips4
```

---

## References

- [FIPS 140-3 Compliance - Go official docs](https://go.dev/doc/security/fips140)
- [The FIPS 140-3 Go Cryptographic Module - Go Blog](https://go.dev/blog/fips140)
- [crypto/fips140 package](https://pkg.go.dev/crypto/fips140)
- [Go 1.24 FIPS changes - Microsoft](https://devblogs.microsoft.com/go/go-1-24-fips-update/)
