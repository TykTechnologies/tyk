<!-- reqproof:component gateway_api_definition_path_compilation -->
<!-- documents STK-REQ-057 SYS-REQ-145 SW-REQ-132 -->

`STK-REQ-057`, `SYS-REQ-145`, and `SW-REQ-132` cover local gateway API
definition path-compilation helper behavior in `gateway/api_definition.go`:
classic path list compilation, extended endpoint compilation, cache path
compilation, local template loading, transform-template compilation, header
injection compilation, method-transform compilation, hard-timeout compilation,
and request-size compilation.

The proof slice is intentionally local. It does not claim middleware execution,
route matching correctness, upstream behavior, storage durability, gateway
request admission, or final client-visible behavior.

Evidence is provided by focused gateway API definition path-compilation tests in
`gateway/api_definition_test.go`.
