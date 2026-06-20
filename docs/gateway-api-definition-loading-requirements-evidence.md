<!-- reqproof:component gateway_api_definition_loader -->
<!-- documents STK-REQ-056 SYS-REQ-144 SW-REQ-131 -->

`STK-REQ-056`, `SYS-REQ-144`, and `SW-REQ-131` cover local gateway API
definition loading helper behavior in `gateway/api_definition.go`: spec
construction from supplied definitions, dashboard and RPC payload handling,
configured local secret reference replacement, parse helpers, companion OAS/MCP
path derivation, and local file/directory loading.

The proof slice is intentionally local. It does not claim route generation
correctness, middleware execution, persistence durability, dashboard or RPC
service availability, external secret-store availability, network transport
delivery, gateway request admission, or final client-visible behavior.

Evidence is provided by focused gateway API definition loader tests in
`gateway/api_definition_test.go`.
