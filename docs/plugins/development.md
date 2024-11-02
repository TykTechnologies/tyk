# Go plugin development

For effectively developing go plugins, absorb the following:

- [The official plugin package documentation - Warnings](https://pkg.go.dev/plugin)
- [Tutorial: Getting started with multi-module workspaces](https://go.dev/doc/tutorial/workspaces)

<TOC>

## Setting up your environment

To develop plugins, you'll need:

- Go based on the gateway version (from go.mod)
- Git to check out gateway source code
- A folder with plugins to build

Set up a workspace, which is going to look like:

- `/tyk` - the checkout
- `/plugins` - the plugins

A sample [Taskfile.yml](Taskfile.yml) is provided here.

```
task: Available tasks for this project:
* all:             Do everything
* checkout:        Checking out tyk
* workspace:       Create workspace
* test:            Test plugin build
* clean:           Clean workspace
```

Let's break down the individual steps from a run of `task all`.

### 1. Checking out tyk

```
task: [checkout] git clone --branch release-5.3.6 https://github.com/TykTechnologies/tyk.git tyk-release-5.3.6 || true
```

The example checkout uses a particular `release-5.3.6` branch, to match a
release. With newer `git` version, you may pass `--branch v5.3.6` and it
would use the tag. In case you want to use the tag it's also possible to
navigate into the folder and issue `git checkout tags/v5.3.6`.

### 2. Preparing the workspace - plugins

```
task: [workspace] mkdir -p plugins
task: [workspace:plugins] rm -f go.mod go.sum
task: [workspace:plugins] go mod init testplugin
go: creating new go.mod: module testplugin
task: [workspace:plugins] go mod edit -go "1.22.6"
task: [workspace:plugins] wget -q https://raw.githubusercontent.com/TykTechnologies/custom-go-plugin/refs/heads/master/go/src/CustomGoPlugin.go
```

The internal `workspace:plugins` step ensures a few things:

1. create a plugin, create go.mod,
2. set go.mod go version to what's set in gateway,
3. have some code to compile in the folder

At this point, we don't have a workspace yet.

### 3. Creating the workspace

```
task: [workspace] go work init ./tyk-release-5.3.6
task: [workspace] go work use ./plugins
task: [workspace] cd plugins && go get github.com/TykTechnologies/tyk@c808608b9a3c44b2ef0e060f8d3f3d2269582a1c
```

These are the final steps on how to create the workspace. The last step
is used to update go.mod with the gateway commit corresponding to the
checkout. The Taskfile wires some automation to achieve this:

```
workspace:
  desc: "Create workspace"
  vars:
    release: tyk-release-5.3.6
    commit:
      sh: git rev-parse HEAD
    go:
      sh: go mod edit -json ./{{.release}}/go.mod | jq .Go -r
  cmds:
    - mkdir -p plugins
    - task: workspace:plugins
      vars:
        go: '{{.go}}'
    - go work init ./{{.release}}
    - go work use ./plugins
    - cd plugins && go get github.com/TykTechnologies/tyk@{{.commit}}
```

When creating the workspace, the `commit` and `go` variables are
populated directly from the checked out repository. After this step
you're able to use `go mod tidy` in the plugins folder.

### 4. Testing out the plugin

```
task: [test] cd tyk-release-5.3.6 && go build -tags=goplugin -trimpath -race .
task: [test] cd plugins           && go build -trimpath -race -buildmode=plugin .
```

The above few steps build gateway, and the plugin.

```
task: [test] ./tyk-release-5.3.6/tyk plugin load -f plugins/testplugin.so -s AuthCheck
time="Oct 01 21:29:24" level=info msg="--- Go custom plugin init success! ---- "
[file=plugins/testplugin.so, symbol=AuthCheck] loaded ok, got 0x7fdcd650f980
```

We can use the built gateway binary to test plugin loading without
invoking the plugin symbol like a request would. However, as
demonstrated, the plugins `init` function is invoked, printing to the
log.

### 5. Summary

We've put together an end-to-end build environment for both the gateway
and the plugin. However, runtime environments have additional
restrictions which the plugin developer must pay attention to.

Compatibility in general is a big concern around plugins; since the
plugins are tightly coupled to gateway, they need to be built with some
consideration to the restrictions around them.

Continue with [Loading Go Plugins into Tyk](https://tyk.io/docs/product-stack/tyk-gateway/advanced-configurations/plugins/golang/loading-go-plugins/).

## Common issues

### Plugin compiler

We provide a plugin build environment to manage compatibility restrictions
for plugins. The plugin compiler ensures compatibility between the system
architecture and the go version for your target environment.

The plugin compiler also provides cross-compilation support.

Continue with [Go Plugin Compiler](https://tyk.io/docs/product-stack/tyk-gateway/advanced-configurations/plugins/golang/go-plugin-compiler/).

### Build flag restrictions

It's a requirement that build flags for gateway match build flags for the
plugin. One such flag that need to be included in builds is `-trimpath`:

> `-trimpath` - remove all file system paths from the resulting executable.
>
> Instead of absolute file system paths, the recorded file names will
> begin with either "go" (for the standard library), or a module
> path@version (when using modules), or a plain import path (when using GOPATH).

The Gateway uses `-trimpath` to clear local build environment details
from the binary, and it must in turn be used for the plugin build as
well. The use of the flag increases compatibility for plugins.

For more detailed restrictions, please see [debugging.md](debugging.md).
