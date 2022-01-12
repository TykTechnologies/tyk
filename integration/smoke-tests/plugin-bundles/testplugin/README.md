# Multiple middlewares

This single plugin shared library includes 4 plugins

- Authentication middleware plugin - `Authenticate`
- Pre request middleware plugin - `PreRequestLogger`
- Post request middleware plugin - `AddHelloWorldHeader`
- Response middleware plugin - `AddResponseHeader`

The detailed config can be viewed in `manifest.json`

This plugin is intended to be served as a bundle so that the bundle flow for tyk go plugin is tested