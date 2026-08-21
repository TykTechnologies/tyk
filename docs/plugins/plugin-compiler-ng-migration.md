---
title: Migrating a build to the next-generation plugin compiler
tags:
    - custom plugin
    - golang
    - go plugin
    - plugin compiler
    - migration
description: Checklist for moving an existing plugin build to the NG compiler image, and how to roll back
date: "2026-08-14"
---

For someone who already builds Go plugins with `tykio/tyk-plugin-compiler` (or the `-ee` / `-fips` repositories) and wants to try the next-generation (NG) image. NG is opt-in and is maintained alongside the existing compiler; you do not have to migrate.

## What changes

The image tag. NG is published from the same three repositories with a `-ng` suffix:

| Existing | NG |
|---|---|
| `tykio/tyk-plugin-compiler:<version>` | `tykio/tyk-plugin-compiler:<version>-ng` |
| `tykio/tyk-plugin-compiler-ee:<version>` | `tykio/tyk-plugin-compiler-ee:<version>-ng` |
| `tykio/tyk-plugin-compiler-fips:<version>` | `tykio/tyk-plugin-compiler-fips:<version>-ng` |

The most recent NG release at the time of writing is `v5.15.0-alpha11-ng`.

```diff
 docker run --rm -v "$(pwd):/plugin-source" \
-  tykio/tyk-plugin-compiler-ee:v5.15.0-alpha11 plugin.so
+  tykio/tyk-plugin-compiler-ee:v5.15.0-alpha11-ng plugin.so
```

## What does not change

- Entrypoint `/build.sh` and working directory `/go/src/github.com/TykTechnologies/tyk`.
- The container runs as root (`User: 0`).
- Plugin source is mounted at `/plugin-source`, and the built `.so` is moved back there.
- Positional arguments: `plugin_name`, optional `plugin_id`, optional `GOOS`, optional `GOARCH`.
- Environment variables you already use (`GOOS`, `GOARCH`, `BUILD_TAG`, `GO_GET`, `GO_TIDY`, `DEBUG`, `PLUGIN_SOURCE_PATH`, `PLUGIN_BUILD_PATH`).
- Output naming: `{plugin_name%.*}_{GATEWAY_VERSION}_{GOOS}_{GOARCH}.so`.

## One behavioural difference to check before you switch

NG never rewrites an existing plugin `go.mod` module path, and never rewrites import paths in your Go sources. The existing compiler does both when `plugin_id` is supplied. `plugin_id` in NG only names the build directory (and supplies the generated module name when your plugin has no `go.mod` at all).

If you pass a `plugin_id` purely to get a unique output file name, nothing changes for you. If you relied on the module-path rewrite to load two builds of the same plugin into one Gateway, set distinct module paths in your own `go.mod` files instead.

## What to check after the first NG build

1. **Validation output.** NG validates the artifact before it is moved back to `/plugin-source`. Confirm the run ends with `== validation OK: <file> ==` and read the `[ok]` lines. A failure is a real incompatibility, not a compiler bug — the same problem would otherwise appear as `plugin was built with a different version of package ...` when the Gateway loads the plugin. `VALIDATE=0` skips validation if you need the artifact anyway.
2. **glibc floor.** The validation output reports the highest required GLIBC symbol version and the ceiling it is checked against (2.17 in published NG images). If your plugin now fails this check, a cgo dependency is pulling in a symbol newer than the pinned floor; that plugin would have needed a newer runtime glibc than the pinned target.
3. **FIPS mode.** With the FIPS image, confirm the validator reports a `FIPS:` line. `EDITION=ee-fips but the plugin shows NO FIPS crypto` means the artifact would be rejected by a FIPS Gateway.
4. **Edition tags.** With the EE or FIPS image, confirm the `edition: 'ee' build tag present` line.
5. **Architecture.** If you cross-compile, confirm the reported ELF machine type matches your target. Remember that the compiler image itself is `linux/amd64`, so pass `GOARCH` explicitly rather than relying on the host.
6. **Load the plugin.** Published NG images do not contain the Gateway self-test binary, so run the `tyk plugin load` check against a Gateway container rather than inside the compiler container.

## Rolling back

Drop the `-ng` suffix and rerun. Nothing else in your build needs to change, and the existing compiler continues to be published for released Gateway versions:

```bash
docker run --rm -v "$(pwd):/plugin-source" \
  tykio/tyk-plugin-compiler-ee:v5.15.0-alpha11 plugin.so
```

Rebuild the plugin after rolling back rather than reusing an NG artifact, so the plugin and the toolchain that produced it stay consistent.
