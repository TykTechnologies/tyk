# How to write a test
- Create a sub-directory for your test
- Implement a script `test.sh` in your directory which will run the test and signal failure via exit code
- Document the test in this file (if needed)

# How it works
## Plugin compiler
- compiles `foobar-plugin/main.go` & `helloworld-plugin/main.go` using the appropriate plugin-compiler
- mounts api definitions in `foobar-plugin` and `helloworld-plugin` into apps/

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `plugin-compiler/test.sh`.

The foobar plugin adds a header `Foo: Bar` to all requests. 
The helloworld plugin adds a header `Hello: World`

The test loads 2 APIs using foobar plugin and 2 APIs using helloworld plugin, it thereby ensures
that plugin compiler can be used to compiler multiple plugins, also it ensures that same plugin can be used in
multiple APIs

## Python plugins
The `bundler` service serves two purposes:
- compiles src/middleware.py using src/manifest.json using `tyk bundle`. This is done during the build phase.
- serves `bundle.zip` from `tyk bundle` for the `gw` service

The plugin adds a header `Foo: Bar` to all requests. 

Run it as `./test.sh <version>`. Depends on `<version>` being available in Docker Hub. See `python-plugins/test.sh`.
