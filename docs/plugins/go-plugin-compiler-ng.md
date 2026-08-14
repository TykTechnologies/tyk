---
title: Next-generation Go plugin compiler (NG)
tags:
    - custom plugin
    - golang
    - go plugin
    - plugin compiler
    - cross compilation
    - fips
description: Opt-in next-generation Tyk plugin compiler image, published alongside the existing plugin compiler
date: "2026-08-14"
---

The *next-generation plugin compiler* (referred to as *NG*) is a second build of the Tyk plugin compiler image. It is published from the same repositories as the existing compiler, with a `-ng` suffix on the tag, and it takes the same arguments. It is opt-in: both compilers are maintained in parallel and nothing about the existing compiler changes.

If you are new to building Go plugins, start with [Custom Go plugin development flow]({{< ref "product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-development-flow" >}}) and [Tyk Plugin Compiler]({{< ref "product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-plugin-compiler" >}}). This page only describes what NG adds and how it differs.

{{< note success >}} **Note**

At the time of writing, NG images are published on alpha tags only, the most recent being `v5.15.0-alpha11-ng`. The existing plugin compiler remains the image used for released Gateway versions. {{< /note >}}

## What NG is and why it exists

The plugin compiler exists because a Go plugin must be built with the same toolchain, build tags and build flags as the Gateway that loads it. NG keeps that contract and adds four things:

- **Cross-compilation from a single image.** One NG image can target `linux/amd64`, `linux/arm64` and `linux/s390x`.
- **A pinned glibc link sysroot.** The C library, C runtime objects and headers used for the link come from a sysroot pinned to glibc 2.17, not from the image's own (newer) base OS. Plugins therefore keep the same low glibc symbol floor even though the image itself is built on a modern base.
- **Post-build validation.** After a successful build the artifact is inspected and the build *fails* with an actionable message if the architecture, Go version, edition build tags, FIPS mode or glibc ceiling do not match what was requested. Set `VALIDATE=0` to skip.
- **A Docker Hardened Images (DHI) base.** The C toolchain is provisioned by Docker into the base image. There is no build-time `apt-get` in the compiler image, and the image build fails closed if the base is missing a tool it expects.

Scanned with Tyk's published VEX feed applied, the NG image reports 0 CRITICAL and 0 HIGH findings. See [Scanning the image](#scanning-the-image-for-vulnerabilities) for how to reproduce that.

## Choosing between the two compilers

| | Existing plugin compiler | NG plugin compiler |
|---|---|---|
| Image tag | `tykio/tyk-plugin-compiler:<version>` | same repository, `-ng` suffix: `tykio/tyk-plugin-compiler:<version>-ng` |
| Published for | released Gateway versions | alpha tags at the time of writing |
| Invocation | `/build.sh <plugin_name> [plugin_id] [GOOS] [GOARCH]`, source at `/plugin-source` | identical |
| Target architectures | `linux/amd64`, `linux/arm64` | `linux/amd64`, `linux/arm64`, `linux/s390x` (CE); `linux/amd64`, `linux/arm64` (EE and FIPS) |
| glibc floor of the produced plugin | follows the image's base OS | pinned by a glibc 2.17 link sysroot shipped in the image |
| Post-build checks | none | architecture, Go version, edition tags, FIPS evidence, glibc ceiling, linked libraries |
| `plugin_id` behaviour | rewrites the plugin `go.mod` module path and Go import paths | only names the build directory; an existing `go.mod` is never rewritten |
| Base image | `tykio/golang-cross` | Docker Hardened Images customization with a Docker-provisioned toolchain |
| Gateway test binary inside the image | present (`/usr/local/bin/tyk`) | not present in published images |

Use the existing compiler if you are building plugins for a released Gateway version and your build works today. Try NG if you want to build for more than one architecture from one image, want the build to fail early rather than at `plugin.Open` time, or need the vulnerability posture of the hardened base. Because the interface is identical, trying NG is usually just changing the image tag.

## Image variants

NG is published from the same three Docker Hub repositories as the existing compiler:

| Edition | Image | Default `EDITION` |
|---|---|---|
| Community | `tykio/tyk-plugin-compiler:<version>-ng` | `ce` |
| Enterprise | `tykio/tyk-plugin-compiler-ee:<version>-ng` | `ee` |
| Enterprise + FIPS | `tykio/tyk-plugin-compiler-fips:<version>-ng` | `ee-fips` |

The edition is baked into each image, together with the build tags, `GOFIPS140`/`GOEXPERIMENT` settings and the list of architectures that edition's Gateway is published for. You do not need to set `EDITION` yourself; you cannot use the CE image to produce an EE or FIPS plugin, and the build fails with an explicit message if you try.

Match the image to the Gateway you will load the plugin into. An `ee` plugin will not load into a CE Gateway, and a FIPS Gateway will reject a plugin built without FIPS crypto.

{{< note success >}} **Note**

The DHI base used by NG is a supply-chain hardening measure. It is not in itself a FIPS compliance claim: FIPS plugin crypto comes from the FIPS Gateway's Go toolchain and the edition settings baked into the FIPS image. {{< /note >}}

## Quick start

Mount your plugin source at `/plugin-source` and pass the output name. The entrypoint is `/build.sh`, the working directory is `/go/src/github.com/TykTechnologies/tyk` and the container runs as root, exactly as with the existing compiler:

```bash
docker run --rm -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler:v5.15.0-alpha11-ng plugin.so
```

The built plugin is moved back into `/plugin-source`, so it appears in your working directory. The output file name is `{plugin_name%.*}_{GATEWAY_VERSION}_{GOOS}_{GOARCH}.so` — for the example above, `plugin_v5.15.0_linux_amd64.so`.

For Enterprise or FIPS plugins, change the repository:

```bash
docker run --rm -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler-ee:v5.15.0-alpha11-ng plugin.so

docker run --rm -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler-fips:v5.15.0-alpha11-ng plugin.so
```

### Positional arguments

The four positional arguments are unchanged from the existing compiler:

1. `plugin_name` — the output name, for example `vendor-plugin.so`. It must be a bare file name, not a path.
2. `plugin_id` — optional. It selects the build directory inside the container, and it is used in the generated module name when your plugin has no `go.mod`.
3. `GOOS` — optional override.
4. `GOARCH` — optional override.

```bash
docker run --rm -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler:v5.15.0-alpha11-ng plugin.so "$(date +%s)"
```

{{< note success >}} **Note**

NG never rewrites an existing plugin `go.mod` module path or the import paths in your Go sources. The existing compiler rewrites both when `plugin_id` is supplied. If your workflow relied on that rewrite to build the same plugin twice into one Gateway, set the module path in your own `go.mod` instead. {{< /note >}}

### Environment variables

| Variable | Effect |
|---|---|
| `VALIDATE` | `VALIDATE=0` skips post-build validation. Any other value (or unset) runs it. |
| `EDITION` | `ce`, `ee` or `ee-fips`. Defaults to the edition baked into the image. `FIPS=1` is accepted as an alias for `EDITION=ee-fips`. |
| `GOOS`, `GOARCH` | Alternative to the third and fourth positional arguments. |
| `BUILD_TAG` | Extra build tags, appended to the `goplugin` tag and any edition tag. |
| `GO_GET` | `GO_GET=1` runs `go get github.com/TykTechnologies/tyk@<gateway sha>` before building. |
| `GO_TIDY` | `GO_TIDY=1` runs `go mod tidy` before building. |
| `DEBUG` | `DEBUG=1` turns on shell tracing and prints a diff of the prepared build directory. |
| `PLUGIN_SOURCE_PATH` | Source mount point. Defaults to `/plugin-source`. |
| `PLUGIN_BUILD_PATH` | Build directory inside the container. Defaults to a directory derived from `plugin_name` and `plugin_id`. |
| `PLUGIN_TRIMPATH` | Overrides the `-trimpath` setting derived from the Gateway. Only needed for old Gateway releases whose binaries do not record the flag. |
| `PLUGIN_BUILD_METHOD` | `auto` (default), `workspace`, `replace` or `gopath`. `auto` picks a Go workspace on Go 1.18 and newer; the other methods exist for older Gateway releases. |

The glibc target (`TYK_GLIBC_TARGET`) is a property of the image, not a runtime knob: each image ships exactly one sysroot set, and published NG images ship glibc 2.17. Overriding the variable at run time fails because no other sysroot is present.

## Cross-compiling

Pass the target as the third and fourth positional arguments:

```bash
docker run --rm -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler:v5.15.0-alpha11-ng plugin.so "" linux arm64
```

or as environment variables:

```bash
docker run --rm -e GOOS=linux -e GOARCH=arm64 -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler:v5.15.0-alpha11-ng plugin.so
```

Both forms produce `plugin_v5.15.0_linux_arm64.so`. `s390x` works the same way with the CE image:

```bash
docker run --rm -e GOARCH=s390x -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler:v5.15.0-alpha11-ng plugin.so
```

The set of allowed target architectures is checked against the architectures the chosen edition's Gateway is published for. Asking the EE or FIPS image for `s390x` fails with a message listing the architectures that edition supports, because no such Gateway exists to load the plugin.

The published compiler images themselves are `linux/amd64`. On an arm64 host (for example Apple silicon) Docker runs them through emulation, so do not rely on the host architecture to select the target — pass `GOARCH` explicitly.

## Post-build validation

After the build, and before the artifact is moved back to `/plugin-source`, NG inspects the produced `.so` and checks:

- it is a 64-bit ELF shared object built with `-buildmode=plugin`;
- the ELF machine type matches the requested `GOARCH`;
- the Go toolchain recorded in the plugin matches the Gateway's Go version;
- for `ee` and `ee-fips`, that the `ee` build tag is present;
- for `ee-fips`, that the binary carries FIPS crypto evidence (an enabled `GOFIPS140` setting or explicit boringcrypto evidence);
- the linked libraries — a plugin linked against musl or `libpython` is rejected, because the Gateway image provides neither;
- the highest required `GLIBC_x.y` symbol version is not newer than the image's glibc target;
- as a warning only, that the `github.com/TykTechnologies/tyk` revision the plugin links matches the Gateway revision.

Successful checks are printed as `[ok]` lines, for example a line reporting the architecture and a line reporting `GLIBC ceiling: 2.17 <= 2.17`, and the run ends with `== validation OK: <file> ==`.

### Interpreting a failure

Failures are printed as `ERROR (plugin validation): ...` and stop the build with a non-zero exit code. The common ones:

- **`Go toolchain mismatch: plugin=..., gateway=...`** — the plugin was built with a different Go version than the Gateway. Use the compiler image whose tag matches your Gateway release.
- **`GOARCH mismatch: built ..., expected ...`** — the produced object is for a different architecture than requested. Check that you did not set `GOARCH` in two places at once.
- **`plugin requires GLIBC_x.y which is NEWER than the supported target GLIBC_2.17`** — your C code (or a cgo dependency) pulled in a symbol that only exists in a newer glibc. Either avoid that function or accept that the plugin needs a newer runtime than the pinned floor.
- **`EDITION=ee ... lacks 'ee'`** — the plugin does not carry the enterprise build tag; you are probably using the CE image for an EE Gateway.
- **`EDITION=ee-fips but the plugin shows NO FIPS crypto`** — build with the FIPS image.
- **`plugin links musl libc`** or **`plugin links libpython...`** — the plugin depends on a library the Gateway image does not ship, and would fail to load at runtime.

Each of these would otherwise surface as an opaque `plugin was built with a different version of package ...` error when the Gateway loads the plugin. If you need the artifact regardless — for example to inspect it — rerun with `-e VALIDATE=0`.

## Scanning the image for vulnerabilities

NG is built on a Docker Hardened Images base, and Docker publishes affectedness decisions (VEX statements) for the packages it provisions. Those decisions are what make the difference between a raw scan and the reported result.

Scanning without VEX gives 84 HIGH/CRITICAL rows across 60 distinct CVEs. Essentially all of them are in kernel headers (`linux-libc-dev`), `perl`, `busybox` and `libcurl4t64` — packages Docker has assessed as not affecting the image.

With Tyk's VEX repository configured the same scan reports 0 CRITICAL and 0 HIGH.

### Configuring the VEX repository

Create the Trivy VEX repository configuration at `$XDG_DATA_HOME/.trivy/vex/repository.yaml`, or at `$HOME/.trivy/vex/repository.yaml` when `XDG_DATA_HOME` is not set:

```yaml
repositories:
  - name: tyk-dhi
    url: https://tyktechnologies.github.io/tyk-vex-records
    enabled: true
```

Download the repository, then scan with `--vex repo`:

```bash
trivy vex repo download

trivy image --scanners vuln --severity HIGH,CRITICAL \
  --vex repo --show-suppressed \
  tykio/tyk-plugin-compiler-ee:v5.15.0-alpha11-ng
```

{{< note success >}} **Note**

Three things are easy to get wrong here:

1. The `url` is the site **root**. Sub-paths such as `/tyk` or `/dhi` do not exist and return 404.
2. If you have other VEX repositories configured, list `tyk-dhi` **first**. A repository that merely lists a package shadows lower-priority repositories for that package, even when it carries no statement for the CVE in question. This was reported upstream as `aquasecurity/trivy` discussion 11083, with a fix proposed in PR 11082.
3. Pass `--show-suppressed`. Without it, suppressed findings disappear from the report with no indication that anything was suppressed. {{< /note >}}

## Known limitations

- NG images are published on alpha tags at the time of writing. They are not published for released Gateway versions.
- The compiler images are `linux/amd64` only; on an arm64 host they run under emulation.
- Each image ships one glibc sysroot set (2.17 in published images). There is no run-time switch to a different glibc target.
- The edition is fixed per image. `EDITION=ee` or `EDITION=ee-fips` fails in an image that was not built for that edition.
- `linux/s390x` is only available for the CE edition, because EE and FIPS Gateways are not published for that architecture.
- Published NG images deliberately contain no Gateway executable. The existing compiler image installs one, which means it ships the Gateway inside a build tool; NG builds it only into unpublished gate images used by CI to prove a plugin loads, and the release build fails if the binary is present. The practical consequence is that you cannot run `tyk plugin load` inside the compiler container -- load the plugin into a Gateway container instead.
- `plugin_id` no longer rewrites your module path or import paths (see [Positional arguments](#positional-arguments)).

## Relationship to the existing plugin compiler

Both compilers are maintained together. NG does not replace the existing plugin compiler, and existing users need change nothing: the existing images continue to be built and published for released Gateway versions from the same repositories and tags as before.

NG is opt-in and interface-compatible. Its entrypoint, working directory, positional arguments, environment variables, source mount point and output naming are the same, so moving a build to NG is normally a tag change and moving back is the same change in reverse.

NG is currently published on alpha tags only. No date has been set for it to
become the default, and none is implied by this page. Until that decision is
made, treat NG as available for evaluation and for builds where its
cross-compilation, validation or hardened base are useful, and treat the
existing compiler as the path for released Gateway versions.

See `plugin-compiler-ng-migration.md` in this directory for a checklist when moving an
existing build, including how to roll back.
