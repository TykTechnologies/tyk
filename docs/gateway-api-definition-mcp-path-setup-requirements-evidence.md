<!-- reqproof:component gateway_api_definition_mcp_path_setup -->
<!-- documents STK-REQ-060 SYS-REQ-148 SW-REQ-135 -->

`STK-REQ-060`, `SYS-REQ-148`, and `SW-REQ-135` cover local gateway API
definition MCP path setup helper behavior in `gateway/api_definition.go`:
MCP primitive extraction into extended paths, built-in MCP operation internal
path insertion, primitive-to-VEM map construction, allow-list flag derivation,
JSON-RPC router initialization, and extended-path aggregation/whitelist flag
selection.

The proof slice is intentionally local. It does not claim JSON-RPC request
execution, primitive authorization enforcement, middleware runtime behavior,
route admission, persistence, upstream behavior, or final client-visible
outcomes.

Evidence is provided by focused gateway API definition helper tests in
`gateway/api_definition_test.go`.
