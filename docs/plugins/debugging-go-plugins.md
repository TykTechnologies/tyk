---
title: Debugging Go plugins
tags:
    - custom plugin
    - golang
    - go plugin
    - middleware
description: Debugging guide for Go plugins
date: "2024-10-11"
---

Plugins are native Go code compiled to a binary shared object file. The code may depend on `cgo` and require libraries like `libc` provided by the runtime environment. The following are some debugging steps for diagnosing issues arising from using plugins.

## Warnings

The [Plugin package - Warnings](https://pkg.go.dev/plugin#hdr-Warnings) section in the Go documentation outlines several requirements which can't be ignored when working with plugins. The most important restriction is the following:

> Runtime crashes are likely to occur unless all parts of the program (the application and all its plugins) are compiled using exactly the same version of the toolchain, the same build tags, and the same values of certain flags and environment variables.

We provide the *Tyk Plugin Compiler* docker image, which we strongly recommend is used to build plugins compatible with the official Gateway releases. This tool provides the cross compilation toolchain, Go version used to build the release, and ensures that compatible flags are used when compiling plugins, like `-trimpath`, `CC`, `CGO_ENABLED`, `GOOS`, `GOARCH`.

The *Plugin Compiler* also works around known Go issues such as:

- https://github.com/golang/go/issues/19004
- https://www.reddit.com/r/golang/comments/qxghjv/plugin_already_loaded_when_a_plugin_is_loaded/

Supplying the argument `build_id` to the *Plugin Compiler* ensures the same plugin can be rebuilt. The *Plugin Compiler* does this by replacing the plugin `go.mod` module path.

Continue with [Tyk Plugin Compiler](https://tyk.io/docs/product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-plugin-compiler/).

### Examples

When working with Go plugins, it's easy to miss the restriction that the plugin at the very least must be built with the same Go version, and the same flags (notably `-trimpath`) as the Tyk Gateway on which it is to be used.

If you miss an argument (for example `-trimpath`) when building the plugin, the Gateway will report an error when your API attempts to load the plugin, for example:

```
task: [test] cd tyk-release-5.3.6 && go build -tags=goplugin -trimpath .
task: [test] cd plugins && go build -buildmode=plugin .
task: [test] ./tyk-release-5.3.6/tyk plugin load -f plugins/testplugin.so -s AuthCheck
tyk: error: unexpected error: plugin.Open("plugins/testplugin"): plugin was built with a different version of package internal/goarch, try --help
```

Usually when the error hints at a standard library package, the build flags between the Gateway and plugin binaries don't match.

Other error messages may be reported, depending on what triggered the issue. For example, if you omitted `-race` in the plugin but the gateway was built with `-race`, the following error will be reported:

```
plugin was built with a different version of package runtime/internal/sys, try --help
```

Strictly speaking:

- Build flags like `-trimpath`, `-race` need to match.
- Go toolchain / build env needs to be exactly the same.
- For cross compilation you must use the same `CC` value for the build (CGO).
- `CGO_ENABLED=1`, `GOOS`, `GOARCH` must match with runtime.

When something is off, you can check what is different by using the `go version -m` command for the Gateway (`go version -m tyk`) and plugin (`go version -m plugin.so`). Inspecting and comparing the output of `build` tokens usually yields the difference that caused the compatibility issue.

## Plugin compatibility issues

This is a short list of cases when dependencies may be causing problems.

- A Gateway dependency does not have a `go.mod` and the plugin wants to use it.
- Gateway and plugin have a shared dependency: the same version must be used by the plugin.
- A plugin wants to use a different dependency version.

The cases need to be expanded, but the process for each is:

**Case 1:**

- Plugin uses Gateway as a dependency but wants to use *A*
- *A* does not have a `go.mod`, so a pseudo version is generated on both ends of the build
- Result: build success, error when loading plugin due to a version mismatch

Fix: update to remove dependency *A*, or use a version with `go.mod`

**Case 2:**

- Plugin uses Gateway as a dependency and wants to use a shared dependency
- As the dependency has `go.mod`, the version matches
- Dependency is promoted to *direct* in `go.mod`
- Expect: you have to keep the dependency in sync with Gateway

**Case 3:**

- Plugin uses Gateway as a dependency but wants to use a different version of a shared dependency
- It's likely using a major release with `/v4` or similar works like a charm (new package)
- Expectation: If it's just a different version of the same package, loading the plugin will fail

We recommend that all dependencies should follow Go package metaversion, however the reality is most Gateway dependencies follow a basic v1 semver which doesn't break import paths for every release.

## List plugin symbols

Sometimes it's useful to list symbols from a plugin. For example, we can list the symbols as they are compiled into our testplugin:

```
# nm -gD testplugin.so | grep testplugin
00000000014db4b0 R go:link.pkghashbytes.testplugin
000000000170f7d0 D go:link.pkghash.testplugin
000000000130f5e0 T testplugin.AddFooBarHeader
000000000130f900 T testplugin.AddFooBarHeader.deferwrap1
000000000130f980 T testplugin.AuthCheck
0000000001310100 T testplugin.AuthCheck.deferwrap1
000000000130f540 T testplugin.init
0000000001310ce0 T testplugin.init.0
0000000001ce9580 D testplugin..inittask
0000000001310480 T testplugin.InjectConfigData
0000000001310180 T testplugin.InjectMetadata
0000000001d2a3e0 B testplugin.logger
0000000001310cc0 T testplugin.main
0000000001310820 T testplugin.MakeOutboundCall
0000000001310c40 T testplugin.MakeOutboundCall.deferwrap1
```

This command prints other symbols that are part of the binary. In the worst case, a build compatibility issue may cause a crash in the Gateway due to an unrecoverable error and this can be used to further debug the binaries produced.

A very basic check to ensure Gateway/plugin compatibility is using the built in `go version -m <file>`:

```
[output truncated]
	build	-buildmode=exe
	build	-compiler=gc
	build	-race=true
	build	-tags=goplugin
	build	-trimpath=true
	build	CGO_ENABLED=1
	build	GOARCH=amd64
	build	GOOS=linux
	build	GOAMD64=v1
	build	vcs=git
	build	vcs.revision=1db1935d899296c91a55ba528e7b653aec02883b
	build	vcs.time=2024-09-24T12:54:26Z
	build	vcs.modified=false
```

These options should match between the Gateway binary and the plugin. You can use the command for both binaries and then compare the outputs.
