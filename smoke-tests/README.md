# How to write a test
- Create a sub-directory for your test
- Implement a script `test.sh` in your directory which will run the test and signal failure via exit code
- Document the test in this file (if needed)

# Note
The tests under this directory (`smoke-tests/`) are smoke tests maintained by a squads
to test a very specific functionality during the build. Regular tests that should be part of the
ci process should go to `ci/tests/`

# How it works

## Plugin aliasing
- compiles `foobar-plugin/main.go` & `helloworld-plugin/main.go` using the appropriate plugin-compiler
- mounts api definitions in `foobar-plugin` and `helloworld-plugin` into apps/

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `plugin-compiler/test.sh`.

The foobar plugin adds a header `Foo: Bar` to all requests.
The helloworld plugin adds a header `Hello: World`

The test loads 2 APIs using foobar plugin and 2 APIs using helloworld plugin, it thereby ensures
that plugin compiler can be used to compiler multiple plugins, also it ensures that same plugin can be used in
multiple APIs

