<!-- reqproof:component gateway_api_definition_lifecycle -->
<!-- documents STK-REQ-055 SYS-REQ-143 SW-REQ-130 -->

`STK-REQ-055`, `SYS-REQ-143`, and `SW-REQ-130` cover local gateway API
definition lifecycle helper behavior in `gateway/api_definition.go`: API-level
and global session-lifetime precedence selection, unload hook execution and
local state clearing, HTTP/TCP/TLS validation dispatch with explicit missing
listen-port errors, and OAS streaming extension marker detection.

The proof slice is intentionally local. It does not claim full API loading,
route generation, request matching, middleware execution, persistence
durability, dashboard or RPC synchronization, network transport behavior,
gateway request admission, or final client-visible behavior.

Evidence is provided by focused gateway API definition helper tests in
`gateway/api_definition_test.go`.
