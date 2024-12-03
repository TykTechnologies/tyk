---
title: Custom Go plugin development flow
tags:
    - custom plugin
    - golang
    - go plugin
    - middleware
    - debugging go plugins
description: Development flow working with Go Plugins
date: "2024-10-11"
---

We recommend that you familiarize yourself with the following official Go documentation to help you work effectively with Go plugins:

- [The official plugin package documentation - Warnings](https://pkg.go.dev/plugin)
- [Tutorial: Getting started with multi-module workspaces](https://go.dev/doc/tutorial/workspaces)

{{< note success >}} **Note**

Plugins are currently supported only on Linux, FreeBSD, and macOS, making them unsuitable for applications intended to be portable. {{< /note >}}

Plugins need to be compiled to native shared object code, which can then be loaded by Tyk Gateway. It's important to understand the need for plugins to be compiled using exactly the same environment and [build flags]({{< ref "product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-development-flow#build-flags" >}}) as the Gateway. To simplify this and minimise the risk of compatibility problems, we recommend the use of [Go workspaces](https://go.dev/blog/get-familiar-with-workspaces), to provide a consistent environment.

## Setting up your environment

To develop plugins, you'll need:

- Go (matching the version used in the Gateway, which you can determine using `go.mod`).
- Git to check out Tyk Gateway source code.
- A folder with the code that you want to build into plugins.

We recommend that you set up a *Go workspace*, which, at the end, is going to contain:

- `/tyk-release-x.y.z` - the Tyk Gateway source code
- `/plugins` - the plugins
- `/go.work` - the *Go workspace* file
- `/go.work.sum` - *Go workspace* package checksums

Using the *Go workspace* ensures build compatibility between the plugins and Gateway.

### 1. Checking out Tyk Gateway source code

```
git clone --branch release-5.3.6 https://github.com/TykTechnologies/tyk.git tyk-release-5.3.6 || true
```

This example uses a particular `release-5.3.6` branch, to match Tyk Gateway release 5.3.6. With newer `git` versions, you may pass `--branch v5.3.6` and it would use the tag. In case you want to use the tag it's also possible to navigate into the folder and issue `git checkout tags/v5.3.6`.

### 2. Preparing the Go workspace

Your Go workspace can be very simple:

1. Create a `.go` file containing the code for your plugin.
2. Create a `go.mod` file for the plugin.
3. Ensure the correct Go version is in use.

As an example, we can use the [CustomGoPlugin.go](https://github.com/TykTechnologies/custom-go-plugin/blob/master/go/src/CustomGoPlugin.go) sample as the source for our plugin as shown:

```
mkdir -p plugins
cd plugins
go mod init testplugin
go mod edit -go $(go mod edit -json go.mod | jq -r .Go)
wget -q https://raw.githubusercontent.com/TykTechnologies/custom-go-plugin/refs/heads/master/go/src/CustomGoPlugin.go
cd -
```

The following snippet provides you with a way to get the exact Go version used by Gateway from it's [go.mod](https://github.com/TykTechnologies/tyk/blob/release-5.3.6/go.mod#L3) file:

- `go mod edit -json go.mod | jq -r .Go` (e.g. `1.22.7`)

This should be used to ensure the version matches between gateway and the plugin.

To summarize what was done:

1. We created a plugins folder and initialzed a `go` project using `go mod` command.
2. Set the Go version of `go.mod` to match the one set in the Gateway.
3. Initialzied the project with sample plugin `go` code.

At this point, we don't have a *Go workspace* but we will create one next so that we can effectively share the Gateway dependency across Go modules.

### 3. Creating the Go workspace

To set up the Go workspace, start in the directory that contains the Gateway and the Plugins folder. You'll first, create the `go.work` file to set up your Go workspace, and include the `tyk-release-5.3.6` and `plugins` folders. Then, navigate to the plugins folder to fetch the Gateway dependency at the exact commit hash and run `go mod tidy` to ensure dependencies are up to date.

Follow these commands:

```
go work init ./tyk-release-5.3.6
go work use ./plugins
commit_hash=$(cd tyk-release-5.3.6 && git rev-parse HEAD)
cd plugins && go get github.com/TykTechnologies/tyk@${commit_hash} && go mod tidy && cd -
```

The following snippet provides you to get the commit hash exactly, so it can be used with `go get`.

- `git rev-parse HEAD`

The Go workspace file (`go.work`) should look like this:

```
go 1.22.7

use (
	./plugins
	./tyk-release-5.3.6
)
```

### 4. Building and validating the plugin

Now that your *Go workspace* is ready, you can build your plugin as follows:

```
cd tyk-release-5.3.6 && go build -tags=goplugin -trimpath . && cd -
cd plugins           && go build -trimpath -buildmode=plugin . && cd -
```

These steps build both the Gateway and the plugin.

You can use the Gateway binary that you just built to test that your new plugin loads into the Gateway without having to configure and then make a request to an API using this command:

```
./tyk-release-5.3.6/tyk plugin load -f plugins/testplugin.so -s AuthCheck
```

You should see an output similar to:

```
time="Oct 14 13:39:55" level=info msg="--- Go custom plugin init success! ---- "
[file=plugins/testplugin.so, symbol=AuthCheck] loaded ok, got 0x76e1aeb52140
```

The log shows that the plugin has correctly loaded into the Gateway and that its `init` function has been successfully invoked.

### 5. Summary

In the preceding steps we have put together an end-to-end build environment for both the Gateway and the plugin. Bear in mind that runtime environments may have additional restrictions beyond Go version and build flags to which the plugin developer must pay attention.

Compatibility in general is a big concern when working with Go plugins: as the plugins are tightly coupled to the Gateway, consideration must always be made for the build restrictions enforced by environment and configuration options.

Continue with [Loading Go Plugins into Tyk](https://tyk.io/docs/product-stack/tyk-gateway/advanced-configurations/plugins/golang/loading-go-plugins/).

## Debugging Golang Plugins

Plugins are native Go code compiled to a binary shared object file. The code may depend on `cgo` and require libraries like `libc` provided by the runtime environment. The following are some debugging steps for diagnosing issues arising from using plugins.

### Warnings

The [Plugin package - Warnings](https://pkg.go.dev/plugin#hdr-Warnings) section in the Go documentation outlines several requirements which can't be ignored when working with plugins. The most important restriction is the following:

> Runtime crashes are likely to occur unless all parts of the program (the application and all its plugins) are compiled using exactly the same version of the toolchain, the same build tags, and the same values of certain flags and environment variables.

We provide the *Tyk Plugin Compiler* docker image, which we strongly recommend is used to build plugins compatible with the official Gateway releases. This tool provides the cross compilation toolchain, Go version used to build the release, and ensures that compatible flags are used when compiling plugins, like `-trimpath`, `CC`, `CGO_ENABLED`, `GOOS`, `GOARCH`.

The *Plugin Compiler* also works around known Go issues such as:

- https://github.com/golang/go/issues/19004
- https://www.reddit.com/r/golang/comments/qxghjv/plugin_already_loaded_when_a_plugin_is_loaded/

Supplying the argument `build_id` to the *Plugin Compiler* ensures the same plugin can be rebuilt. The *Plugin Compiler* does this by replacing the plugin `go.mod` module path.

Continue with [Tyk Plugin Compiler](https://tyk.io/docs/product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-plugin-compiler/).

### Using Incorrect Build Flags

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

### Plugin Compatibility Issues

Below are some common situations where dependencies might cause issues:

- The `Gateway` has a dependency without a `go.mod` file, but the plugin needs to use it.
- Both the `Gateway` and the plugin share a dependency. In this case, the plugin must use the exact same version as the `Gateway`.
- The plugin requires a different version of a shared dependency.

Here’s how to handle each case:

**Case 1: Gateway dependency lacks `go.mod`**

- The plugin depends on the `Gateway`, which uses dependency *A*.
- *A* doesn’t have a `go.mod` file, so a pseudo version is generated during the build.
- Result: The build completes, but the plugin fails to load due to a version mismatch.

**Solution:** Update the code to remove dependency *A*, or use a version of *A* that includes a `go.mod` file.

**Case 2: Shared dependency with version matching**

- The plugin and `Gateway` share a dependency, and this dependency includes a `go.mod` file.
- The version matches, and the dependency is promoted to *direct* in `go.mod`.
- Outcome: You’ll need to keep this dependency version in sync with the `Gateway`.

**Case 3: Plugin requires a different version of a shared dependency**

- The plugin and `Gateway` share a dependency, but the plugin needs a different version.
- If the other version is a major release (e.g., `/v4`), it’s treated as a separate package, allowing both versions to coexist.
- If it’s just a minor/patch difference, the plugin will likely fail to load due to a version conflict.

**Recommendation:** For best results, use Go package versions that follow the Go module versioning (metaversion). However, keep in mind that many `Gateway` dependencies use basic `v1` semantic versioning, which doesn’t always enforce strict versioned import paths.

### List plugin symbols

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
