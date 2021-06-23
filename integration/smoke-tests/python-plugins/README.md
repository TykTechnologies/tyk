# How does it work?

The `bundler` service serves two purposes:
- compiles src/middleware.py using src/manifest.json using `tyk bundle`. This is done during the build phase.
- serves `bundle.zip` from `tyk bundle` for the `gw` service

The plugin adds a header `Foo: Bar` to all requests. 
