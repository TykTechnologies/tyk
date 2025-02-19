# Plugin compiler tests

This is the test suite for the plugin compiler. Plugin compatibility
requirements are very strict. As documented in the
[plugin](https://pkg.go.dev/plugin) package, particularly:

> Applications that use plugins may require careful configuration to
ensure that the various parts of the program be made available in the
correct location in the file system (or container image). By contrast,
deploying an application consisting of a single static executable is
straightforward.

> Runtime crashes are likely to occur unless all parts of the program
(the application and all its plugins) are compiled using exactly the same
version of the toolchain, the same build tags, and the same values of
certain flags and environment variables.

> Similar crashing problems are likely to arise unless all common
dependencies of the application and its plugins are built from exactly
the same source code.

These are only some of the restrictions around plugins.

## Taskfile

The test suite is set up using https://taskfile.dev.

The following variables are set as defaults:

| Variable name | Default value                        |
| ------------- | ------------------------------------ |
| tag           | v0.0.0                               |
| base          | tykio/golang-cross:1.22-bullseye     |
| dockerfile    | ci/images/plugin-compiler/Dockerfile |
| image         | internal/plugin-compiler             |
| sha           | `$(git rev-parse HEAD)`              |
| root          | `$(git rev-parse --show-toplevel)`   |

Use `task -l` to list available targets, or read on.

Example: Run a plugin subtest against a release image.

```
task test:qa-plugin image=tykio/tyk-plugin-compiler:v5.3.9-rc4
```

## Building and testing plugin compiler locally

In order to build the plugin compiler images locally from source,
you must issue `task build` in this folder.

To override the base image, you would issue:

```
task base=golang:1.20
```

The default action runs `build` and `test` targets.

We can test the following steps:

- building plugin compiler locally
- plugin compilation
- plugin loading (tyk load -f -s)

Additionally, running the smoke test against a tag is possible.

Example:

```
./test.sh v5.2.1
```

The test takes optional `GATEWAY_IMAGE` and `PLUGIN_COMPILER_IMAGE` from
the environment, enabling testing on images that are not published to
docker hub. This functionality is used in the CI, to run smoke tests on
the docker images built from the release pipeline.
