# MCP Protocol Requirements Evidence

<!-- documents STK-REQ-019 -->
<!-- documents SYS-REQ-107 -->
<!-- documents SW-REQ-025 -->
<!-- documents SW-REQ-026 -->

This document records the MCP protocol helper proof slice. The slice is limited
to `internal/mcp` helper behavior plus the shared `internal/jsonrpc` router
interface, route-result shape, and JSON-RPC method VEM prefix constants that
those helpers consume. It does not claim gateway middleware sequencing, API
definition synthesis, session-right retrieval, analytics, network transport
behavior, or final HTTP status generation.

`STK-REQ-019` owns the MCP client need for deterministic routing and list
filtering. `SYS-REQ-107` owns the request/response-visible helper decisions:
MCP method-to-VEM route construction, primitive VEM path classification, VEM
prefix registration, MCP list access-rule evaluation, JSON-RPC list-response
filtering, and pass-through handling for unsupported or malformed responses.

`SW-REQ-025` owns `internal/mcp` routing and prefix helpers and the shared
`internal/jsonrpc` declarations they use for router conformance, route results,
and method-level VEM paths. Evidence in `internal/mcp/mcp_test.go` and
`internal/mcp/router_test.go` covers non-empty prefixes, primitive VEM path
classification, JSON-RPC method-prefix registration, tool, resource, prompt,
and operation routing through the `jsonrpc.Router` interface, exact resource
mapping precedence, longest wildcard precedence, default JSON-RPC method VEM
fallback construction, and missing or invalid primitive parameter errors.

`SW-REQ-026` owns `internal/mcp` list filtering. Evidence in
`internal/mcp/list_filter_test.go` covers string extraction, allowed and blocked
rule precedence, anchored full-match regex behavior, invalid-regex exact-match
fallback, malformed item fail-open behavior, unsupported JSON-RPC body
pass-through, successful envelope re-encoding, Unicode item names, and list
configuration inference order.
