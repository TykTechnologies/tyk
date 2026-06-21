<!-- reqproof:component gateway_api_spec_request_versioning -->
<!-- documents STK-REQ-061 SYS-REQ-149 SW-REQ-136 -->

`STK-REQ-061`, `SYS-REQ-149`, and `SW-REQ-136` cover local gateway API
spec request/version helper behavior in `gateway/api_definition.go`: URL status
mapping, CORS/whitelist/internal path decisions, request version extraction from
headers/query/path, request validity status selection from already-loaded
version/path state, API expiration checks, default-version selection, ambiguous
default-version detection, listen-path stripping, version-path stripping, and
proxy path sanitization.

The proof slice is intentionally local. It does not claim authentication,
policy enforcement, middleware execution, upstream behavior, persistence,
network transport behavior, or final client-visible responses.

Evidence is provided by focused gateway API definition helper tests in
`gateway/api_definition_test.go`.
