# MCP Protocol Requirements Evidence

<!-- documents STK-REQ-019 -->
<!-- documents SYS-REQ-107 -->
<!-- documents SW-REQ-025 -->
<!-- documents SW-REQ-026 -->
<!-- documents SW-REQ-037 -->

This document records the MCP protocol helper proof slice. The slice is limited
to `internal/mcp` helper behavior, the shared `internal/jsonrpc` router
interface, route-result shape, and JSON-RPC method VEM prefix constants that
those helpers consume, plus the `apidef/mcp` embedded-schema validation helpers.
It does not claim gateway middleware sequencing, gateway API loading or API
definition synthesis beyond in-process MCP schema validation, session-right
retrieval, analytics, network transport behavior, or final HTTP status
generation.

`STK-REQ-019` owns the MCP client need for deterministic routing and list
filtering and the operator-facing need for deterministic MCP API-definition
schema validation. `SYS-REQ-107` owns the request/response-visible helper
decisions: MCP method-to-VEM route construction, primitive VEM path
classification, VEM prefix registration, MCP list access-rule evaluation,
JSON-RPC list-response filtering, pass-through handling for unsupported or
malformed responses, and MCP OAS document validation against supported embedded
schemas.

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

`SW-REQ-037` owns `apidef/mcp` schema loading and validation helpers. Evidence
in `apidef/mcp/validator_test.go` and `apidef/mcp/linter_test.go` covers
embedded schema loading, `x-tyk-api-gateway` extension injection into supported
OAS schemas, OAS 3.0 `definitions` and OAS 3.1 `$defs` selection, default schema
version selection, requested major/minor/patch version resolution, valid MCP OAS
documents for tools/resources/prompts/PRM, aggregated validation errors for
malformed documents, explicit unsupported-version and malformed-version errors,
schema acceptance of forward-compatible middleware fields, and extension
presence in returned schemas. This evidence does not claim schema completeness
beyond the embedded files under test or any gateway loader/runtime outcome.
