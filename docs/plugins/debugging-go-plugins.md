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

Plugins are native go code compiled to a binary shared object file. The code may depend on CGO and require libraries like libc provided by the runtime environment. The following are some debugging steps for diagnosing issues arising from using plugins.

## Warnings

The [plugin package - Warnings](https://pkg.go.dev/plugin#hdr-Warnings) section outlines several requirements which can't be ignored. The most important restriction is the following:

> Runtime crashes are likely to occur unless all parts of the program (the application and all its plugins) are compiled using exactly the same version of the toolchain, the same build tags, and the same values of certain flags and environment variables.

We provide a Plugin Compiler docker image, which should be used to build plugins compatible with the official gateway releases and their architectures. It provides the cross compilation toolchain, Go version used to build the release, and ensure compatible flags are used when compiling plugins, like `-trimpath`, `CC`, `CGO_ENABLED`, `GOOS`, `GOARCH`.

The plugin compiler also works around known Go issues.

- https://github.com/golang/go/issues/19004
- https://www.reddit.com/r/golang/comments/qxghjv/plugin_already_loaded_when_a_plugin_is_loaded/

The argument plugin_id ensures the same plugin can be rebuilt. The plugin compiler does this by replacing the plugin go.mod module path.

Continue with [Go Plugin Compiler](https://tyk.io/docs/product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-plugin-compiler/).

### Examples

When working with Go plugins, it's easy to miss the restriction that the plugin at the very least requires to be built with the same Go version, and the same flags, notably `-trimpath`, which is part of the Gateway official release.

If you miss an argument like forgetting `-trimpath` for the plugin build, you'll get a load error like the one below. Usually when the error hints at a standard library package, the build flags between the binaries don't match. For example, if gateway is compiled with `-race`, the plugin needs to be compiled with the flag as well to be compatible.

```
task: [test] cd tyk-release-5.3.6 && go build -tags=goplugin -trimpath .
task: [test] cd plugins && go build -buildmode=plugin .
task: [test] ./tyk-release-5.3.6/tyk plugin load -f plugins/testplugin.so -s AuthCheck
tyk: error: unexpected error: plugin.Open("plugins/testplugin"): plugin was built with a different version of package internal/goarch, try --help
```

Other error messages may occur, depending on what triggered the issue. For example, if you omitted `-race` in the plugin but the gateway was built with `-race`, the error reported is:

```
plugin was built with a different version of package runtime/internal/sys, try --help
```

Stricly speaking:

- build flags like `-trimpath`, `-race` need to match
- go toolchain / build env needs to be exactly the same
- cross compilation means using the same `CC` value for the build (CGO)
- matching `CGO_ENABLED=1`, `GOOS`, `GOARCH` with runtime

When something is off, proofing these can be done with `go version -m tyk` and `go version -m plugin.so` for the plugin, inspecting and comparing the output of `build` tokens usually yields the difference that caused the compatibility issue.

## Plugin compatibility issues

This is a short list of cases when dependencies may be causing problems.

- A gateway dependency does not have a go.mod and plugin wants to use it,
- A gateway dependency has a shared dependency, same version must be used,
- A plugin wants to use a different dependency version

The cases need to be expanded, but the process for each is:

Case 1:

- Plugin uses gateway as a dependency but wants to use A
- A does not have a go.mod, so a pseudo version is generated on both ends of the build
- Expect: build success, error when loading plugin due to a version mismatch

Fix: update to remove dependency A, or use a version with go.mod;

Case 2:

- Plugin uses gateway as a dependency and wants to use a shared dependency
- As the dependency has go.mod, the version matches
- Dependency is promoted to direct in go.mod
- Expect: user has to keep dependency in sync with gateway

Case 3:

- Plugin uses gateway as a dependency but wants to use a different version of a dependency
- It's likely using a major release with `/v4` or similar works like a charm (new package)
- Expectation: If it's just a different version of the same package, loading the plugin will fail

It's definitely recommended that all dependencies would follow go package metaversion, however the reality is most gateway dependencies follow a basic v1 semver which doesn't break import paths for every release.

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

The command prints other symbols that are part of the binary. In the worst case, a build compatibility issue may cause a crash in the gateway due to an unrecoverable error and this can be used to further debug the binaries produced.

A very basic check to ensure gateway/plugin compatibility is using the built in `go version -m <file>`:

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

It's typical that these options should match between the gateway binary and the plugin, and you can use the command for both binaries.
