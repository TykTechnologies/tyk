# MCP Protocol Requirements Evidence

<!-- documents STK-REQ-019 -->
<!-- documents SYS-REQ-107 -->
<!-- documents SW-REQ-025 -->
<!-- documents SW-REQ-026 -->
<!-- documents SW-REQ-037 -->
<!-- documents SW-REQ-039 -->
<!-- documents SW-REQ-040 -->
<!-- documents SW-REQ-043 -->
<!-- documents SW-REQ-048 -->
<!-- documents SW-REQ-064 -->

This document records the MCP protocol helper proof slice. The slice is limited
to `internal/mcp` helper behavior, the shared `internal/jsonrpc` router
interface, route-result shape, and JSON-RPC method VEM prefix constants that
those helpers consume, the `apidef/mcp` embedded-schema validation helpers, the
local `internal/service/gojsonschema` facade used by that validation path, and
the user-package MCP access-right data model consumed by MCP helper flows, and
the `apidef/oas` MCPPrimitive helper shape and build-mode guard used by MCP API-definition helper
flows. It does not claim gateway middleware sequencing, gateway API loading or
API definition synthesis beyond in-process MCP schema validation and local
MCPPrimitive extraction helpers, policy merge behavior, session-right
retrieval, persistence, analytics, network transport behavior, upstream
JSON-schema library correctness, reverse-proxy/access-log error classification,
or final HTTP status generation.

`STK-REQ-019` owns the MCP client need for deterministic routing and list
filtering and the operator-facing need for deterministic MCP API-definition
schema validation. `SYS-REQ-107` owns the request/response-visible helper
decisions: MCP method-to-VEM route construction, primitive VEM path
classification, VEM prefix registration, MCP list access-rule evaluation,
JSON-RPC list-response filtering, pass-through handling for unsupported or
malformed responses, and MCP OAS document validation against supported embedded
schemas, plus the user-package data-model helpers that preserve MCP and
JSON-RPC access-right configuration shape before those helper flows consume it,
and the local OAS MCPPrimitive helper shape used to carry supported middleware
configuration while omitting MCP-incompatible middleware families during
extended-path extraction, including build-mode-specific guard behavior for
direct Operation extraction inputs.

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

`SW-REQ-039` owns the local `internal/service/gojsonschema` facade used by MCP
schema validation. Evidence in `internal/service/gojsonschema` tests covers the
exposed bytes and Go loaders, validation call, valid-result reporting,
invalid-result error exposure, result-error string access, and format-checker
registry availability. This evidence does not claim correctness of the upstream
JSON Schema implementation.

`SW-REQ-040` owns the local `internal/errors` facade and validation-error
formatter used by MCP schema validation. Evidence in `internal/errors` tests
covers standard error construction/comparison/joining/unwrapping/as-casting
symbol exposure, unsupported-error identity, empty aggregate formatting,
single-error formatting, and newline-separated multi-error formatting. This
evidence does not claim reverse-proxy or access-log error classification.

`SW-REQ-043` owns the local `user` MCP access-right and primitive-limit data
model consumed by MCP and JSON-RPC access-control helper flows. Evidence in
`user/mcp_access_test.go` covers empty and zero-state detection for access rules
and MCP access rights, JSON roundtrips for access rules, JSON-RPC method limits,
MCP primitive limits, and configured MCP access fields, supported primitive type
validation for tool/resource/prompt values, rejection of empty, unknown, and
case-mismatched primitive types, and omission of zero MCP access-control fields
from JSON. This evidence does not claim policy merge behavior, gateway session
lookup, persistence backends, middleware enforcement, list filtering itself,
analytics, network transport behavior, or final HTTP status generation.

`SW-REQ-048` owns the local `apidef/oas.MCPPrimitive` helper behavior used by
MCP API-definition helper flows. Evidence in
`apidef/oas/mcp_primitive_reqproof_test.go` covers Operation-compatible JSON
shape preservation, nil primitive and nil output safety, omission of
MCP-incompatible middleware families during extraction, preservation of
supported request/response header, rate-limit, and request-size middleware, and
deterministic repeated extraction. This evidence does not claim full OAS
conversion, gateway API loading, session-right lookup, middleware execution,
policy merge behavior, persistence, analytics, network transport behavior, or
final HTTP status generation.

`SW-REQ-064` owns the local `apidef/oas` MCPPrimitive extraction guard selected
by release and non-release build tags. Evidence in
`apidef/oas/mcp_primitive_guard_reqproof_test.go` covers accepted MCPPrimitive
and nil inputs in all builds, direct Operation input rejection by panic in
non-release builds, and direct Operation no-op behavior under the `release`
build tag. This evidence does not claim full OAS conversion, gateway API
loading, middleware execution, policy merge behavior, session-right lookup,
persistence, analytics, network transport behavior, or final HTTP status
generation.
