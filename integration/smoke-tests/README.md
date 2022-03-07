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