# How to write a test
- Create a sub-directory for your test
- Implement a script `test.sh` in your directory which will run the test and signal failure via exit code
- Document the test in this file (if needed)

# How it works
## Plugin compiler
- compiles testplugin/main.go using the appropriate plugin-compiler
- mounts testplugin/apidef.json into apps/

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `plugin-compiler/test.sh`.

The plugin adds a header `Foo: Bar` to all requests.

## Python plugins
The `bundler` service serves two purposes:
- compiles src/middleware.py using src/manifest.json using `tyk bundle`. This is done during the build phase.
- serves `bundle.zip` from `tyk bundle` for the `gw` service

The plugin adds a header `Foo: Bar` to all requests. 

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `python-plugins/test.sh`.

## Basic Functionality testing
The `test.sh` script sets up the tyk-gateway with the `<version>` provided.
It sets the gateway up using `docker-compose` and includes a very basic api endpoint that
proxies requests to `http://httpbin.org/get`.

The corresponding test passes an argument through to this endpoint, and verifies whether it is
returned properly thereby confirming that the binary can actually start and run a basic api endpoint.

The file `api_test.sh` implements the actual test bit, `test.sh` invokes the `api_test.sh` to execute the
test.

We also have a file `pkg_test.sh` which tests the debian/rpm packages from the release workflow, which
also ultimately invokes the `api_test.sh`
