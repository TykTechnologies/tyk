#!/bin/bash
# validate-plugin.sh <plugin.so>
#
# Turns opaque "plugin was built with a different version of package ..." /
# "wrong ELF class" runtime errors into actionable BUILD-TIME diagnostics.
#
# Inputs (env, all optional except sensible defaults):
#   EXPECT_GOARCH        target GOARCH (e.g. amd64, arm64)
#   EXPECT_GOOS          target GOOS (default linux)
#   GATEWAY_GO_VERSION   e.g. go1.25.10  (must match the plugin's toolchain)
#   MAX_GLIBC            highest allowed GLIBC symbol version (e.g. 2.31)
#   GW_TYK_REVISION      expected github.com/TykTechnologies/tyk pseudo-version/sha
#
# Exits non-zero with a clear message on the first hard failure.
set -uo pipefail

SO="${1:?usage: validate-plugin.sh <plugin.so>}"
EXPECT_GOOS="${EXPECT_GOOS:-linux}"
fail() { echo "ERROR (plugin validation): $*" >&2; exit 1; }
ok()   { echo "  [ok] $*"; }

[ -f "$SO" ] || fail "artifact not found: $SO"
echo "== validating $(basename "$SO") =="

# Locate tools (image ships file + binutils + go).
READELF="$(command -v readelf || command -v llvm-readelf)"
FILE="$(command -v file)"
[ -n "$READELF" ] || fail "readelf not found in image (install binutils)"

# --- 1. file: ELF shared object of the requested architecture ---------------
finfo="$("$FILE" "$SO" 2>/dev/null)"
echo "  file: $finfo"
echo "$finfo" | grep -q "ELF 64-bit"      || fail "not a 64-bit ELF object"
echo "$finfo" | grep -qi "shared object"  || fail "not a shared object (-buildmode=plugin expected)"

machine="$("$READELF" -h "$SO" 2>/dev/null | awk -F: '/Machine/{gsub(/^[ \t]+/,"",$2);print $2}')"
case "${EXPECT_GOARCH:-}" in
  amd64) echo "$machine" | grep -qi "X86-64"          || fail "GOARCH mismatch: built $machine, expected amd64 (X86-64)";;
  arm64) echo "$machine" | grep -qi "AArch64"         || fail "GOARCH mismatch: built $machine, expected arm64 (AArch64)";;
  s390x) echo "$machine" | grep -qiE "S/?390"         || fail "GOARCH mismatch: built $machine, expected s390x (IBM S/390)";;
  "")    : ;;
  *)     echo "  (no machine assertion for GOARCH=$EXPECT_GOARCH)";;
esac
ok "architecture: $machine"

# --- 2. go version -m: toolchain + dependency alignment ---------------------
if command -v go >/dev/null; then
  # `go version -m` is built for executables and intermittently returns NOTHING for a
  # -buildmode=plugin .so (more often under load). Retry, and track whether it was actually
  # readable - so a transient empty read is NOT mistaken for a missing build tag / missing FIPS
  # marker (that mistake caused spurious, load-correlated validation failures). FIPS detection
  # below reads the BINARY itself (load-independent), not this metadata.
  buildinfo=""
  for _try in 1 2 3; do
    buildinfo="$(go version -m "$SO" 2>/dev/null || true)"
    [ -n "$buildinfo" ] && break
    sleep 1
  done
  bi_readable=false; [ -n "$buildinfo" ] && bi_readable=true
  [ "$bi_readable" = true ] || echo "  ! note: go version -m returned no build info for this plugin .so (retried) - tag/dependency checks below defer to the gateway load test."
  plugin_go="$(echo "$buildinfo" | head -1 | awk '{print $2}')"
  # Only accept a real toolchain string (goX.Y[.Z]). Older Go does not expose the
  # toolchain for a -buildmode=plugin .so via `go version -m`, leaving this blank.
  case "$plugin_go" in go1.*) : ;; *) plugin_go="" ;; esac
  image_go="$(go version 2>/dev/null | awk '{print $3}')"
  if [ -n "${GATEWAY_GO_VERSION:-}" ]; then
    if [ -n "$plugin_go" ]; then
      [ "$plugin_go" = "$GATEWAY_GO_VERSION" ] || \
        fail "Go toolchain mismatch: plugin=$plugin_go, gateway=$GATEWAY_GO_VERSION. Go plugins MUST be built with the gateway's exact Go version."
      ok "go toolchain: $plugin_go (matches gateway)"
    elif [ "$image_go" = "$GATEWAY_GO_VERSION" ]; then
      # Build-info unreadable (older Go .so). The plugin was produced by THIS image,
      # whose Go IS the gateway's Go - so the toolchain matches by construction, and
      # the subsequent `tyk plugin load` is the definitive ABI check.
      ok "go toolchain: build-info unreadable (older Go .so); built by image Go $image_go == gateway"
    else
      fail "Go toolchain mismatch: plugin build-info unreadable AND image Go=$image_go != gateway=$GATEWAY_GO_VERSION."
    fi
  else
    ok "go toolchain: ${plugin_go:-unreadable (older Go .so)}"
  fi
  # buildmode must be plugin
  echo "$buildinfo" | grep -q -- "-buildmode=plugin" || echo "  ! warning: -buildmode=plugin not recorded in build info"
  # Edition: ee/ee-fips plugins must carry the 'ee' build tag; ee-fips must also
  # carry FIPS crypto. A mismatch here would fail plugin.Open on that edition.
  edition="$(echo "${EXPECT_EDITION:-ce}" | tr 'A-Z' 'a-z')"
  if [ "$edition" = "ee" ] || [ "$edition" = "ee-fips" ]; then
    tagsval="$(echo "$buildinfo" | grep -oE '\-tags=[^[:space:]]+' | head -1 | sed 's/-tags=//')"
    if [ -n "$tagsval" ]; then
      case ",$tagsval," in
        *,ee,*) ok "edition: 'ee' build tag present" ;;
        *) fail "EDITION=$edition but the plugin's -tags=$tagsval lacks 'ee' - it will not match an EE/FIPS Gateway." ;;
      esac
    elif [ "$bi_readable" = true ]; then
      echo "  ! note: EDITION=$edition - no -tags line in build info; deferring the 'ee' check to the gateway load test (definitive)."
    else
      # Do NOT fail on a missing marker we could not read: that turns a transient unreadable
      # build info into a spurious failure. The gateway load test (plugin.Open) is definitive.
      echo "  ! note: EDITION=$edition - build info unreadable; the gateway load test is the definitive 'ee' check."
    fi
  fi
  if [ "$edition" = "ee-fips" ]; then
    # Authoritative FIPS check reads the BINARY (deterministic, load-independent) - NOT the
    # build-info metadata, which `go version -m` intermittently fails to surface for a
    # -buildmode=plugin .so (notably under load), which previously caused spurious
    # "no FIPS crypto" failures. boringcrypto links BoringSSL (_goboringcrypto* /
    # crypto/internal/boring symbols); Go-native FIPS-140 compiles in crypto/internal/fips140.
    # build info is only a fallback if symbol scanning is somehow unavailable.
    # IMPORTANT: extract the marker LINES with `grep -o` (reads all input) rather than
    # `grep -q` (closes the pipe early -> SIGPIPEs the huge strings/nm output -> the pipeline
    # reports failure under `set -o pipefail`, which would silently drop back to build info).
    marks=""
    if command -v strings >/dev/null 2>&1; then
      marks="$(strings -a "$SO" 2>/dev/null | grep -oiE '_goboringcrypto|crypto/internal/(boring|fips140)' | sort -u || true)"
    fi
    if [ -z "$marks" ] && command -v nm >/dev/null 2>&1; then
      marks="$(nm "$SO" 2>/dev/null | grep -oiE 'boringcrypto|crypto/internal/(boring|fips140)' | sort -u || true)"
    fi
    fipskind=""
    if printf '%s\n' "$marks" | grep -qiE '_?goboringcrypto|crypto/internal/boring'; then
      fipskind="boringcrypto (binary symbols)"
    elif printf '%s\n' "$marks" | grep -qi 'crypto/internal/fips140'; then
      fipskind="GOFIPS140 (binary symbols)"
    elif echo "$buildinfo" | grep -qE 'GOFIPS140='; then
      fipskind="$(echo "$buildinfo" | grep -oE 'GOFIPS140=[^[:space:]]+' | head -1) (build-info)"
    elif echo "$buildinfo" | grep -qi 'boringcrypto'; then
      fipskind="boringcrypto (build-info)"
    fi
    if [ -n "$fipskind" ]; then ok "FIPS: $fipskind"
    else fail "EDITION=ee-fips but the plugin shows NO FIPS crypto - no boringcrypto/fips140 symbols in the binary AND no GOFIPS140/boringcrypto in build info. It will not match a FIPS Gateway."
    fi
  fi
  # tyk dependency revision alignment (best-effort; pseudo-version embeds the sha)
  if [ -n "${GW_TYK_REVISION:-}" ]; then
    tykdep="$(echo "$buildinfo" | awk '/[[:space:]]dep[[:space:]]+github.com\/TykTechnologies\/tyk[[:space:]]/{print $3}' | head -1)"
    if [ -n "$tykdep" ]; then
      short="${GW_TYK_REVISION:0:12}"
      if [ "$tykdep" = "(devel)" ]; then
        # Faithful workspace build against the in-image vendored gateway source.
        ok "tyk dependency: (devel) - local workspace build against vendored gateway source"
      elif echo "$tykdep" | grep -q "$short"; then
        ok "tyk dependency: $tykdep (matches gateway revision)"
      else
        echo "  ! warning: plugin links github.com/TykTechnologies/tyk@$tykdep but gateway is $short - verify dependency alignment (build in-tree/workspace, or GO_GET=1)."
      fi
    fi
  fi
else
  echo "  (go not available; skipping build-info checks)"
fi

# --- 3. readelf -d: dynamic deps + interpreter ------------------------------
needed="$("$READELF" -d "$SO" 2>/dev/null | grep NEEDED | sed -E 's/.*\[(.*)\]/\1/' | sort -u)"
echo "  NEEDED: $(echo "$needed" | tr '\n' ' ')"
echo "$needed" | grep -q "^libc.so.6$" || echo "  ! note: libc.so.6 not in NEEDED (CGO_ENABLED=0 build?)"
# Guard against accidental non-glibc / unexpected runtime deps.
if echo "$needed" | grep -qi "musl"; then
  fail "plugin links musl libc - incompatible with the glibc-based Gateway runtime."
fi

# --- 4. readelf --version-info: GLIBC symbol ceiling ------------------------
maxglibc="$("$READELF" --version-info "$SO" 2>/dev/null \
  | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
  | sed 's/GLIBC_//' | sort -uV | tail -1)"
if [ -n "$maxglibc" ]; then
  echo "  max GLIBC symbol required: $maxglibc"
  if [ -n "${MAX_GLIBC:-}" ]; then
    # version compare: highest must be <= MAX_GLIBC
    if [ "$(printf '%s\n%s\n' "$maxglibc" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
      fail "plugin requires GLIBC_$maxglibc which is NEWER than the supported target GLIBC_$MAX_GLIBC. It may fail to load on the Gateway runtime. Rebuild against the glibc-$MAX_GLIBC sysroot."
    fi
    ok "GLIBC ceiling: $maxglibc <= $MAX_GLIBC"
  fi
else
  ok "no versioned GLIBC symbol requirements"
fi

echo "== validation OK: $(basename "$SO") =="
