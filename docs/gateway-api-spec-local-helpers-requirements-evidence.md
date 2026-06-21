<!-- reqproof:component gateway_api_spec_local_helpers -->
<!-- documents STK-REQ-063 SYS-REQ-151 SW-REQ-138 -->

`STK-REQ-063`, `SYS-REQ-151`, and `SW-REQ-138` cover local gateway API
spec helper behavior in `gateway/api_definition.go`: redirect-target path
construction, active OAS and MCP mock detection, enabled virtual endpoint
detection, listen-port matching, and bounded round-robin index selection.

The proof slice is intentionally local. It does not claim reverse-proxy
execution, upstream behavior, mock delivery, virtual endpoint execution,
network binding, load balancing fairness beyond local index calculation, or
final client-visible responses.

Evidence is provided by focused gateway API definition helper tests in
`gateway/api_definition_test.go`.
