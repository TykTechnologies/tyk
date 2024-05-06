# How to write a test

- Create a sub-directory for your test
- Implement a script `test.sh` in your directory
- Document the test in this file (if needed)

When invoking `test.sh`, the first argument needs to be the release
version being tested, e.g. `v5.2.0`. If the test fails, it should exit
with a non-zero exit code.

# How it works

## Requirements

You need docker compose v2 installed to run most tests. Docker compose is
used to bring up an environment from the configured services in
docker-compose.yml files. Generally it's advisable to run this with the
latest docker and docker compose versions installed.

For some extra tests, you'll also need https://taskfile.dev ; whenever
you see a Taskfile.yml, invoking `task` would either run the default
action, or print the available commands.

## Linting

The Taskfile.yml in this directory serves to ensure that the bash scripts
are linted for common issues. The only issue that's excluded is the
following:

```
In ./api-functionality/test.sh line 12:
setup $1
      ^-- SC2086 (info): Double quote to prevent globbing and word splitting.
```

Other issues may appear, but you should be aware of the above. It's
turned off mainly for readability purposes, as we control the scripts
inputs and are not likely to cause harm from a test suite.

To run the linter, invoke `task lint`.

## Run tests offline

To run tests offline, it's done with `task run`. To pass the gateway
release to use, run it as `task tag=v5.2.0 run`, or temporarily modify
the default version in the Taskfile. This is a generic test runner, if
you need to test against particular local docker images, read the
individual test suite details below.

# Test suites

## Plugin compiler

- compiles testplugin/main.go using the appropriate plugin-compiler
- mounts testplugin/apidef.json into apps/

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `plugin-compiler/test.sh`.

It's possible to override the docker images used with:

- `GATEWAY_IMAGE` - if not provided, `tykio/tyk-gateway:<version>` is used.
- `PLUGIN_COMPILER_IMAGE` - if not provided, `tykio/tyk-plugin-compiler:<version>` is used.

The plugin adds a header `Foo: Bar` to all requests.

## Python plugins

The `bundler` service serves two purposes:

- compiles src/middleware.py using src/manifest.json using `tyk bundle`. This is done during the build phase.
- serves `bundle.zip` from `tyk bundle` for the `gw` service

The plugin adds a header `Foo: Bar` to all requests. 

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `python-plugins/test.sh`.

It's possible to override the docker image used with:

- `GATEWAY_IMAGE` - if not provided, `tykio/tyk-gateway:<version>` is used.

## Basic Functionality testing

The `test.sh` script sets up the tyk-gateway with the `<version>`
provided. It sets the gateway up using `docker-compose` and includes a
very basic api endpoint that proxies requests to
`http://httpbin.org/get`.

The corresponding test passes an argument through to this endpoint, and
verifies whether it is returned properly thereby confirming that the
binary can actually start and run a basic api endpoint.

The file `api_test.sh` implements the actual test bit, `test.sh` invokes
the `api_test.sh` to execute the test.

We also have a file `pkg_test.sh` which tests the debian/rpm packages
from the release workflow, which also ultimately invokes the
`api_test.sh`.

It's possible to override the docker images used with:

- `GATEWAY_IMAGE` - if not provided, `tykio/tyk-gateway:<version>` is used.

