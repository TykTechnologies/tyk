#!/bin/bash
# tyk-plugin-compiler entrypoint - DROP-IN compatible with the upstream
# v5.13.0 build.sh. Same positional args, env vars, output naming and
# /plugin-source behaviour. Additions are opt-out and do not change defaults:
#
#   * CC + --sysroot are selected from the pinned glibc link sysroots (2.17 default) so
#     generated plugins keep the SAME low GLIBC symbol floor as the old image
#     regardless of the (modern) base OS glibc.
#   * After a successful build the artifact is validated and the build FAILS
#     with an actionable message on arch / Go-version / GLIBC / dependency
#     mismatch (set VALIDATE=0 to skip).
set -e

# Parse vMAJOR.MINOR.PATCH from the tag. Done in pure bash (was perl upstream) so
# the image needs no perl interpreter - perl was the source of all CRITICAL CVEs
# (CVE-2026-42496 / CVE-2026-8376, no fix available) and is otherwise unused.
GATEWAY_VERSION=""
if [[ "$GITHUB_TAG" =~ v([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    GATEWAY_VERSION="v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
fi

# Plugin compiler arguments (unchanged):
#   1. plugin_name = vendor-plugin.so
#   2. plugin_id   = optional, sets build folder /opt/.../plugin_{name}{id}
#   3. GOOS        = optional override of GOOS
#   4. GOARCH      = optional override of GOARCH
#
# Output name: {plugin_name%.*}_{GATEWAY_VERSION}_{GOOS}_{GOARCH}.so
# Example: ./build.sh plugin.so  ->  plugin_v5.13.0_linux_amd64.so

plugin_name=$1
plugin_id=$2
GOOS=${3:-$(go env GOOS)}
GOARCH=${4:-$(go env GOARCH)}

WORKSPACE_ROOT=$(dirname "$TYK_GW_PATH")
PLUGIN_SOURCE_PATH=${PLUGIN_SOURCE_PATH:-"/plugin-source"}
PLUGIN_BUILD_PATH=${PLUGIN_BUILD_PATH:-"${WORKSPACE_ROOT}/plugin_${plugin_name%.*}$plugin_id"}

# Compatibility target + sysroot location (set by the image; sane defaults).
TYK_GLIBC_TARGET=${TYK_GLIBC_TARGET:-2.31}
TYK_PLUGIN_SYSROOT_BASE=${TYK_PLUGIN_SYSROOT_BASE:-/opt/tyk/sysroots}

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name> <plugin_id>

<plugin_id> is optional
EOF
}

if [ -z "$plugin_name" ] ; then
    usage
    exit 1
fi

# --- CC + sysroot selection -------------------------------------------------
# Pick the C compiler and the matching glibc sysroot for the TARGET arch.
# Works whether the build host is amd64 or arm64 (native preferred, cross OK).
HOST_ARCH=$(go env GOHOSTARCH)
SYSROOT="${TYK_PLUGIN_SYSROOT_BASE}/linux-${GOARCH}-glibc-${TYK_GLIBC_TARGET}"

case "$GOOS/$GOARCH" in
  linux/arm64) GNU_CC=aarch64-linux-gnu-gcc; DYNLD=/lib/ld-linux-aarch64.so.1 ;;
  linux/amd64) GNU_CC=x86_64-linux-gnu-gcc;  DYNLD=/lib64/ld-linux-x86-64.so.2 ;;
  linux/s390x) GNU_CC=s390x-linux-gnu-gcc;   DYNLD=/lib/ld64.so.1 ;;
  *)           GNU_CC=$(go env CC);          DYNLD="" ;;
esac
# Resolve the C compiler. If the per-arch cross gcc is absent there are two cases:
#   * TARGET == host arch  -> the triplet gcc just isn't triplet-named here; the plain native
#                             gcc IS the right compiler (this is the normal Wolfi native build).
#   * TARGET != host arch  -> this image cannot cross-compile. The Wolfi variant ships NO cross
#                             toolchains, so falling back to the native gcc would silently build
#                             wrong-arch objects and fail later with a baffling cgo/link error.
#                             Fail fast with an actionable message instead.
if ! command -v "$GNU_CC" >/dev/null 2>&1; then
  if [ "$GOOS" = "linux" ] && [ "$GOARCH" != "$HOST_ARCH" ]; then
    echo "ERROR: cannot build for linux/$GOARCH - this image has no cross toolchain ('$GNU_CC' is not installed)." >&2
    echo "       This is a NATIVE-ONLY image (the default :vX.Y.Z, or the Wolfi variant): it builds for its host arch ($HOST_ARCH) only." >&2
    echo "       Fix: build for $HOST_ARCH (drop '-e GOARCH', or set GOARCH=$HOST_ARCH)," >&2
    echo "            OR use the -x image (:vX.Y.Z-x), which cross-compiles to amd64/arm64/s390x." >&2
    exit 1
  fi
  GNU_CC=$(go env CC)   # native target, no triplet-named gcc -> the plain native gcc is correct
fi

CC="$GNU_CC"
EXTLDFLAGS=""
if [[ "$GOOS" == "linux" ]]; then
  if [ -d "$SYSROOT/usr/lib" ]; then
    # Pin libc/crt/headers to glibc ${TYK_GLIBC_TARGET} via the sysroot:
    #   --sysroot      : libc.so script + headers resolution
    #   -B .../usr/lib : pick crt1.o/crti.o/crtn.o from the sysroot
    #                    (gcc support objects still come from the compiling gcc)
    #   -isystem       : libc headers
    #   --dynamic-linker: keep the interp path identical to the Gateway image
    # NOTE: OLD Go (<1.18, e.g. v5.0.x on go1.16) links -buildmode=plugin for the NATIVE
    # target arch via the GOLD linker (-fuse-ld=gold); the base image therefore ships
    # binutils-gold, else the external link dies "collect2: cannot find 'ld'" (it is
    # looking for ld.gold). Cross targets use bfd ld and are unaffected; modern Go uses bfd.
    CC="$GNU_CC --sysroot=$SYSROOT -B$SYSROOT/usr/lib -isystem $SYSROOT/usr/include"
    # The EXTERNAL LINK must get the sysroot too. Modern Go threads CC's flags into the
    # cgo link, but OLD Go (<1.18, e.g. building for v5.0.x on go1.16) takes only the
    # compiler BINARY from CC for -extld and DROPS the flags - so the plugin links against
    # the base glibc (observed: GLIBC_2.34, libpthread merged into libc) instead of the
    # sysroot. Passing the same flags via -extldflags pins the link for ALL Go
    # versions (redundant but harmless on modern Go; essential on old Go).
    EXTLDFLAGS="--sysroot=$SYSROOT -B$SYSROOT/usr/lib"
    if [ -n "$DYNLD" ]; then
      CC="$CC -Wl,--dynamic-linker=$DYNLD"
      EXTLDFLAGS="$EXTLDFLAGS -Wl,--dynamic-linker=$DYNLD"
    fi
    echo "INFO: target linux/$GOARCH  CC='$CC'  (glibc<=$TYK_GLIBC_TARGET, host $HOST_ARCH)"
  else
    # No baked toolchain/sysroot for this linux arch. The set of supported target
    # architectures = the sysroots present in the image (currently amd64/arm64/s390x).
    # Adding a new one (e.g. ppc64le) is a small, localised change - see the error.
    supported="$(ls -d "${TYK_PLUGIN_SYSROOT_BASE}"/linux-*-glibc-* 2>/dev/null \
      | sed -E 's#.*/linux-([^-]+)-glibc.*#\1#' | sort -u | paste -sd, -)"
    echo "ERROR: this compiler image has no toolchain/sysroot for linux/$GOARCH." >&2
    echo "       Supported target architectures: ${supported:-none}." >&2
    echo "       To add $GOARCH: install its cross packages + sysroot in Dockerfile.base" >&2
    echo "       and add a CC/dynamic-linker case for it in build.sh, then rebuild." >&2
    exit 1
  fi
fi

# if arch and os present then update the name of file with those params
if [[ "$GOOS" != "" ]] && [[ "$GOARCH" != "" ]] ; then
  plugin_name="${plugin_name%.*}_${GATEWAY_VERSION}_${GOOS}_${GOARCH}.so"
fi

# Copy plugin source into plugin build folder.
mkdir -p "$PLUGIN_BUILD_PATH"
yes | cp -r "$PLUGIN_SOURCE_PATH"/* "$PLUGIN_BUILD_PATH" || true

echo "PLUGIN_BUILD_PATH: ${PLUGIN_BUILD_PATH}"
echo "PLUGIN_SOURCE_PATH: ${PLUGIN_SOURCE_PATH}"

if [[ "$DEBUG" == "1" ]] ; then
	set -x
fi

cd "$PLUGIN_BUILD_PATH"

if [[ "$DEBUG" == "1" ]] ; then
	git config --global init.defaultBranch main
	git config --global user.name "Tit Petric"
	git config --global user.email "tit@tyk.io"
	git init
	git add .
	git commit -m "initial import" .
fi

# ensureGoMod rewrites a go module based on plugin_id if available.
function ensureGoMod {
	NEW_MODULE=tyk.internal/tyk_plugin${plugin_id}

	if [ ! -f "go.mod" ] ; then
		echo "INFO: Creating go.mod"
		go mod init "$NEW_MODULE"
		return
	fi

	if [ -z "${plugin_id}" ] ; then
		echo "INFO: No plugin id provided, keeping go.mod as is"
		return
	fi

	OLD_MODULE=$(go mod edit -json | jq .Module.Path -r)

	case "$OLD_MODULE" in
		*.*) ;;
		*)
		echo "WARN: Plugin go.mod module doesn't contain a dot, consider amending it to prevent conflicts"
		echo "      Current value: $OLD_MODULE"
		echo "    Suggested value: github.com/org/plugin-repo"
		;;
	esac

	go mod edit -module "$NEW_MODULE"
	find ./ -type f -name '*.go' -exec sed -i -e "s,\"${OLD_MODULE},\"${NEW_MODULE},g" {} \;
}

ensureGoMod

# Match the plugin module's `go` directive to the Gateway's Go version. The pinned
# toolchain IS the Gateway's Go, and GOTOOLCHAIN=local refuses a go.mod that asks for a
# newer Go than the toolchain - so a plugin written for a newer line is clamped down to
# build cleanly, and we can compile for OLD Gateways (e.g. v5.0.x on go1.16) without the
# caller hand-editing go.mod. (If the plugin SOURCE genuinely uses language features newer
# than the Gateway's Go, it correctly cannot build - that is inherent to the old target.)
GW_GO_MM="$(go env GOVERSION 2>/dev/null | sed -E 's/^go([0-9]+\.[0-9]+).*/\1/')"
if [ -n "$GW_GO_MM" ] && [ -f go.mod ]; then
	echo "INFO: pinning plugin go directive to Gateway Go ($GW_GO_MM)"
	go mod edit -go="$GW_GO_MM"
fi

# Force the plugin to build against the EXACT vendored Gateway source + dependency
# graph - the core of Go plugin ABI compatibility. Three methods, same outcome:
#   * workspace (default, Go >= 1.18): a go.work makes ./tyk authoritative.
#   * replace   (Go < 1.18, module-mode Gateway): point tyk at ./tyk via a replace directive
#               AND mirror the Gateway's OWN replace directives, so shared transitive deps
#               resolve identically (replaces apply only to the main module, so the plugin
#               must repeat them).
#   * gopath    (Go < 1.18, GOPATH-mode Gateway - e.g. v5.0.x built GO111MODULE=off):
#               an UNTRIMMED GOPATH Gateway bakes each shared package's source PATH
#               (/go/src/<importpath>) into its build ID. A module-mode plugin builds the
#               same code from /go/pkg/mod/<path>@<ver>, so plugin.Open rejects it
#               ("different version of package <dep>") even when the VERSION matches. The fix
#               is to reproduce the Gateway's GOPATH layout: mirror its whole module graph as
#               symlinks under <src-root>/<importpath> and build GO111MODULE=off. Selected
#               automatically when resolve-gateway.sh detected TYK_GATEWAY_SRC_ROOT.
# PLUGIN_BUILD_METHOD = auto | workspace | replace | gopath (default auto).
# The default route is workspace; replace/gopath exist for legacy ad-hoc builds and
# will be retired when pre-1.18 Gateways are no longer supported.
GO_MINOR="$(go env GOVERSION 2>/dev/null | sed -E 's/^go[0-9]+\.([0-9]+).*/\1/')"
PLUGIN_BUILD_METHOD="${PLUGIN_BUILD_METHOD:-auto}"
case "$PLUGIN_BUILD_METHOD" in
	workspace|replace|gopath) METHOD="$PLUGIN_BUILD_METHOD" ;;
	auto)
		if [ -n "${TYK_GATEWAY_SRC_ROOT:-}" ]; then METHOD=gopath
		elif [ "${GO_MINOR:-0}" -ge 18 ] 2>/dev/null; then METHOD=workspace
		else METHOD=replace; fi ;;
	*) echo "ERROR: PLUGIN_BUILD_METHOD must be auto|workspace|replace|gopath (got '$PLUGIN_BUILD_METHOD')" >&2; exit 1 ;;
esac

# Mirror the Gateway's module graph into GOPATH/src layout (symlinks), so shared packages
# build from the same <src-root>/<importpath> the GOPATH-built Gateway baked into its IDs.
layout_gopath() {
	local SR="${TYK_GATEWAY_SRC_ROOT:?gopath method needs TYK_GATEWAY_SRC_ROOT}"
	echo "INFO: downloading Gateway module graph for GOPATH layout under $SR ..."
	( cd "$TYK_GW_PATH" && GO111MODULE=on go mod download all ) 2>&1 | grep -v '^go: downloading' || true
	( cd "$TYK_GW_PATH" && GO111MODULE=on go list -m -json all 2>/dev/null ) \
		| jq -c 'select(.Main != true and ((.Replace.Dir // .Dir) != null))' \
		| while read -r m; do
			p="$(echo "$m" | jq -r '.Path')"
			d="$(echo "$m" | jq -r '.Replace.Dir // .Dir')"
			dest="$SR/$p"
			[ -e "$dest" ] && continue
			mkdir -p "$(dirname "$dest")"
			ln -s "$d" "$dest"
		done
}

GO111MODULE_BUILD=on
if [ "$METHOD" = "gopath" ]; then
	echo "INFO: dependency-alignment method=gopath (Go 1.${GO_MINOR:-?}, GOPATH-built Gateway)"
	layout_gopath
	GO111MODULE_BUILD=off
	cd "$PLUGIN_BUILD_PATH"
elif [ "$METHOD" = "workspace" ]; then
	echo "INFO: dependency-alignment method=workspace (Go 1.${GO_MINOR:-?})"
	cd "$WORKSPACE_ROOT"
	go work init ./tyk
	go work use "./$(basename "$PLUGIN_BUILD_PATH")"
	cd "$PLUGIN_BUILD_PATH"
	if [[ "$GO_GET" == "1" ]] ; then
		go get "github.com/TykTechnologies/tyk@${GITHUB_SHA}"
	fi
	if [[ "$GO_TIDY" == "1" ]] ; then
		go mod tidy
	fi
else
	echo "INFO: dependency-alignment method=replace (Go 1.${GO_MINOR:-?} has no workspaces)"
	cd "$PLUGIN_BUILD_PATH"
	# Point the plugin's tyk dependency at the vendored Gateway source.
	go mod edit -replace "github.com/TykTechnologies/tyk=${TYK_GW_PATH}"
	grep -q 'TykTechnologies/tyk' go.mod \
		|| go mod edit -require "github.com/TykTechnologies/tyk@v0.0.0-00010101000000-000000000000"
	# Mirror the Gateway's own replace directives (local-path replaces are relative to
	# the Gateway dir, so re-anchor them to its absolute path).
	go mod edit -json "${TYK_GW_PATH}/go.mod" 2>/dev/null \
		| jq -r '.Replace[]? | [(.Old.Path + (if .Old.Version then "@"+.Old.Version else "" end)), (.New.Path + (if .New.Version then "@"+.New.Version else "" end))] | @tsv' \
		| while IFS=$'\t' read -r oldspec newspec; do
			case "$newspec" in ./*|../*) newspec="${TYK_GW_PATH}/${newspec}" ;; esac
			go mod edit -replace "${oldspec}=${newspec}"
		done
	go mod tidy
fi

# --- Edition selection (EDITION=ce|ee|ee-fips; default ce) -----------------
# Match the plugin to the EDITION of the Gateway you will load it into:
#   ce      OSS gateway (tags: goplugin)              architectures: amd64/arm64/s390x
#   ee      Enterprise gateway (adds the 'ee' tag)    architectures: amd64/arm64
#   ee-fips Enterprise + FIPS (ee,fips + GOFIPS140)   architectures: amd64/arm64
# The 'ee' tag gates enterprise code and FIPS swaps the crypto module, so a plugin
# built for the wrong edition can fail plugin.Open against that Gateway. The per-
# edition settings are BAKED into this image (resolved from the matching Gateway),
# so this stays correct as EE evolves and across the boringcrypto->native FIPS shift.
# FIPS=1 is kept as a back-compat alias for EDITION=ee-fips.
EDITION="$(echo "${EDITION:-ce}" | tr 'A-Z' 'a-z')"
[[ "${FIPS:-0}" == "1" ]] && EDITION="ee-fips"
# ed_archs = the architectures the chosen edition's Gateway is actually published for
# (baked from the live manifest at image build). The arch guard below is therefore
# DATA-DRIVEN: when Tyk adds e.g. s390x to EE/FIPS, a rebuilt compiler allows it with
# no code change here.
case "$EDITION" in
	ce)
		ed_archs="${TYK_CE_ARCHS:-amd64 arm64 s390x}"
		;;
	ee)
		[[ "${TYK_EE_AVAILABLE:-false}" == "true" ]] || { echo "ERROR: EDITION=ee but no EE Gateway exists for ${GITHUB_TAG:-?}." >&2; exit 1; }
		ed_archs="${TYK_EE_ARCHS:-}"
		[ -n "${TYK_EE_BUILD_TAG:-}" ] && BUILD_TAG="${BUILD_TAG:+${BUILD_TAG},}${TYK_EE_BUILD_TAG}"
		echo "INFO: edition=ee for ${GITHUB_TAG} - tags+='${TYK_EE_BUILD_TAG:-}'"
		;;
	ee-fips)
		[[ "${TYK_FIPS_AVAILABLE:-false}" == "true" ]] || { echo "ERROR: EDITION=ee-fips but no FIPS Gateway exists for ${GITHUB_TAG:-?}." >&2; exit 1; }
		ed_archs="${TYK_FIPS_ARCHS:-}"
		[ -n "${TYK_FIPS_GOFIPS140:-}" ]    && export GOFIPS140="${TYK_FIPS_GOFIPS140}"
		[ -n "${TYK_FIPS_GOEXPERIMENT:-}" ] && export GOEXPERIMENT="${GOEXPERIMENT:+${GOEXPERIMENT},}${TYK_FIPS_GOEXPERIMENT}"
		[ -n "${TYK_FIPS_BUILD_TAG:-}" ]    && BUILD_TAG="${BUILD_TAG:+${BUILD_TAG},}${TYK_FIPS_BUILD_TAG}"
		# boringcrypto FIPS ONLY: the glibc-2.17 sysroot's stdint.h declares the fixed-width ints
		# DIRECTLY, but the FIPS Gateway's newer glibc routes them via __intN_t. cgo bakes that
		# typedef into crypto/internal/boring's generated type, so a plugin built on the raw 2.17
		# header gets a different package build-ID and the Gateway REJECTS it ("different version of
		# package crypto/internal/boring"). Prepend the header-only overlay (built in Dockerfile.base)
		# AHEAD of the sysroot include so boring's type identity matches the Gateway. -isystem ORDER
		# matters (first match wins), hence inserting it right after the compiler. Pure type ALIAS;
		# the LINK still uses the real 2.17 sysroot, so the glibc floor is UNCHANGED. CE/EE and
		# native-GOFIPS140 FIPS never reach this branch. See docs/maintenance.md.
		case ",${TYK_FIPS_GOEXPERIMENT:-}," in
			*,boringcrypto,*)
				OVL="${TYK_PLUGIN_OVERLAY_BASE:-/opt/tyk/sysroot-overlays}/boringcrypto/linux-${GOARCH}-glibc-${TYK_GLIBC_TARGET}/usr/include"
				if [ -f "$OVL/stdint.h" ]; then
					CC="${CC/"$GNU_CC"/$GNU_CC -isystem $OVL}"
					echo "INFO: boringcrypto FIPS - prepended header overlay $OVL (matches Gateway glibc typedefs; glibc floor unchanged)"
				elif [ "${TYK_GLIBC_TARGET}" = "2.17" ]; then
					# FAIL FAST: without the overlay the plugin is GUARANTEED to be rejected by the FIPS
					# Gateway ("different version of package crypto/internal/boring"). Erroring here beats
					# emitting a known-bad .so, and it loudly flags a stale/misbuilt base missing the overlay.
					echo "ERROR: boringcrypto FIPS on glibc-2.17 requires the stdint.h header overlay, but none was found at:" >&2
					echo "         $OVL/stdint.h" >&2
					echo "       The resulting plugin would NOT load into the FIPS Gateway. Rebuild the base image" >&2
					echo "       (Dockerfile.base generates this overlay) - see docs/maintenance.md." >&2
					exit 1
				fi
				;;
		esac
		echo "INFO: edition=ee-fips for ${GITHUB_TAG} - GOFIPS140='${GOFIPS140:-}' tags+='${TYK_FIPS_BUILD_TAG:-}'"
		;;
	*)
		echo "ERROR: unknown EDITION='$EDITION' (use ce | ee | ee-fips)." >&2; exit 1
		;;
esac
# Target arch must be published for this edition's Gateway (else the plugin could
# never be loaded). Data-driven - auto-allows new architectures once Tyk ships them.
ed_archs="$(echo "$ed_archs" | tr ',' ' ')"   # accept comma- or space-separated
case " $ed_archs " in
	*" $GOARCH "*) : ;;
	*) echo "ERROR: edition '$EDITION' has no $GOARCH Gateway (published: ${ed_archs:-none}). If Tyk has since added it, rebuild the compiler for ${GITHUB_TAG:-this release} - no code change needed." >&2; exit 1 ;;
esac

if [[ "$DEBUG" == "1" ]] ; then
	git add .
	git diff --cached
fi

# Pass the sysroot to the external linker via -extldflags (see EXTLDFLAGS above - this is
# what makes OLD Go honor the glibc sysroot at link time, not just at compile time).
ldflags_args=()
[ -n "$EXTLDFLAGS" ] && ldflags_args=(-ldflags "-extldflags '$EXTLDFLAGS'")

# Match the Gateway's -trimpath: a plugin built with a DIFFERENT -trimpath setting than the
# Gateway fails plugin.Open ("different version of package <stdlib>"), because shared-package
# build IDs differ between trimmed and untrimmed builds. TYK_GATEWAY_TRIMPATH is derived from
# the Gateway binary (resolve-gateway.sh); default true preserves the modern behaviour if unset.
# PLUGIN_TRIMPATH (runtime) OVERRIDES the derived value - needed only if the gate reveals a
# go<1.18 Gateway that actually used -trimpath (older Go does not record the flag, so such
# Gateways are derived as no-trimpath; this lets you force the other way without a rebuild).
TRIMPATH="${PLUGIN_TRIMPATH:-${TYK_GATEWAY_TRIMPATH:-true}}"
trimpath_args=()
[ "$TRIMPATH" = "true" ] && trimpath_args=(-trimpath)
echo "INFO: -trimpath=$TRIMPATH (derived=${TYK_GATEWAY_TRIMPATH:-unset}${PLUGIN_TRIMPATH:+, override PLUGIN_TRIMPATH=$PLUGIN_TRIMPATH})"

CC="$CC" CGO_ENABLED=1 GOOS="$GOOS" GOARCH="$GOARCH" GO111MODULE="${GO111MODULE_BUILD:-on}" \
	go build -buildmode=plugin "${trimpath_args[@]}" -tags=goplugin${BUILD_TAG:+,$BUILD_TAG} \
	"${ldflags_args[@]}" -o "$plugin_name"

set +x

# --- Post-build validation (opt-out with VALIDATE=0) ------------------------
if [[ "$VALIDATE" != "0" ]] && [ -x /usr/local/bin/validate-plugin.sh ]; then
	GATEWAY_GO_VERSION="$(go version | awk '{print $3}')" \
	EXPECT_GOARCH="$GOARCH" EXPECT_GOOS="$GOOS" \
	MAX_GLIBC="$TYK_GLIBC_TARGET" \
	GW_TYK_REVISION="$GITHUB_SHA" \
	EXPECT_EDITION="$EDITION" \
	/usr/local/bin/validate-plugin.sh "$PLUGIN_BUILD_PATH/$plugin_name"
fi

mv ./*.so "$PLUGIN_SOURCE_PATH"

# Clean up workspace
rm -f "$WORKSPACE_ROOT/go.work" "$WORKSPACE_ROOT/go.work.sum"
