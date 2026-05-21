# TT-17123 (part 1 of 3) - REST-as-MCP: OAS marker and tool derivation foundation

## Summary

Introduce the API-definition foundation for REST-as-MCP: an OAS marker that lets an operator flag a REST API as MCP-callable, the classic APIDef projection, deterministic OAS-to-tool derivation, adapter APIID helpers, and JSON-schema updates for Dashboard validation. This part adds no gateway runtime wiring; parts 2 and 3 consume these types and helpers.

## Description

Tyk Gateway already supports proxying remote MCP servers. The missing capability is exposing a Tyk-managed REST API as an MCP server so agents can call REST operations as MCP tools while the normal REST API chain remains the source of truth.

This ticket establishes the bottom layer of the stack:

- `x-tyk-api-gateway.server.mcp.enabled` and optional `server.mcp.expose`.
- `apidef.APIDefinition.MCPExposure` / `mcp_exposure`.
- `oas.DeriveSourceTools`, a pure function that walks the source REST OAS into an MCP tool catalogue.
- deterministic adapter identifiers using the `__mcp-server` suffix.
- schema updates so OAS and classic APIDef validation accept the new fields.

Runtime synthesis, SDK streamable HTTP, trust checks, and gateway routing are intentionally out of scope for part 1.

## Expected Behaviour

- Operators can save an OAS REST API with `server.mcp.enabled: true`.
- Classic APIDef payloads can carry `mcp_exposure` without Dashboard schema rejection.
- `oas.DeriveSourceTools` returns deterministic tools from operationIds:
  - path/query/header params become tool arguments with matching locations;
  - JSON object request bodies with properties flatten into `body.<field>` arguments;
  - optional `expose` allow-lists sanitized operationIds;
  - operations marked internal are skipped with a warning;
  - missing/invalid operationIds are skipped with warnings.
- The final stacked contract represents non-object JSON bodies as a single `body` argument with the source schema type. The review hardening for that case lands in part 2 because it patches this helper after part 1.

## Key Changes

- Add `apidef/oas.MCP` and wire it into `oas.Server.Fill` / `ExtractTo`.
- Add `apidef.MCPExposureConfig` and helpers:
  - `IsMCPExposed`
  - `IsPairedMCPAdapterProxy`
  - `IsMCPManaged`
- Add `apidef/oas/mcp_proxy_derive.go` with:
  - `DerivedTool`
  - `DeriveWarning`
  - `DeriveSourceTools`
  - tool-name sanitisation
  - `AdapterAPIID`, `IsAdapterAPIID`, `AdapterSourceAPIID`, `AdapterLoopHost`, `AdapterLoopURL`
- Update:
  - `apidef/schema.json`
  - `apidef/oas/schema/x-tyk-api-gateway.json`
  - `apidef/oas/schema/x-tyk-api-gateway.strict.json`

## Test Cases

- OAS round-trip preserves `server.mcp.enabled` and `server.mcp.expose`.
- Disabled/zero-value marker is omitted on marshal.
- Default exposure exposes every operation with an `operationId`.
- `expose` allow-list filters operations after sanitisation.
- Internal operations are skipped and produce warnings.
- Missing operationId produces a warning and no tool.
- Adapter APIID helper functions are deterministic and reversible.
- Dashboard/classic APIDef schema accepts `mcp_exposure`.

Part 2 extends the derivation tests for array/scalar whole-body JSON schemas.

## Acceptance Criteria

- `go test ./apidef/oas` is green.
- `go build ./apidef/...` succeeds.
- OAS validation accepts `x-tyk-api-gateway.server.mcp`.
- Classic APIDef validation accepts `mcp_exposure`.
- Tool derivation output is deterministic across runs.
- No gateway runtime behaviour changes in this part.

## RFC Review Alignment

These reviewer comments are represented in the technical spec and should be considered when reviewing the part 1 API shape:

- **Endpoint resources:** exposing a REST endpoint as an MCP resource is valid, especially for read-only/static/text-heavy endpoints, but is not mandatory for v1. The current v1 marker exposes REST operations as tools only. A later enrichment layer should allow an operation to be exposed as `tool`, `resource`, or both.
- **Missing `operationId`:** part 1 keeps the rule that operations without an `operationId` do not become tools. The derivation warning is the code-level foundation; part 3/logging and later UI preview work should make skipped operations visible to operators.
- **Tool naming quality:** v1 derives tool names from sanitized `operationId`s. The technical spec records an enrichment layer as the longer-term answer for poor names, display titles, descriptions, parameter examples, annotations, and output schemas.
- **Argument collisions:** v1 currently derives a flat input schema. The technical spec records deterministic collision handling as follow-up work: preserve simple names when unambiguous, and prefix collided names by location such as `path_id`, `query_id`, `header_id`, and `body_id`.
- **Do not mutate source OAS for enrichment:** reviewer feedback agreed that operators may not own the source REST OAS. Future tool/resource enrichment should live on the MCP proxy/config layer, not by rewriting the upstream REST OAS.

## Deferred To Technical Spec / V2

- MCP resources and `resources/list_changed`.
- Tool catalogue enrichment and UI preview of the final `tools/list` shape.
- Poor-name detection beyond strict validity checks.
- Deterministic location-prefixing for collided argument names if not pulled into v1.

## Related Information

- Parent feature: TT-17123 REST-as-MCP.
- Stack order: part 1 -> part 2 -> part 3.
- Part 1 PR: https://github.com/TykTechnologies/tyk/pull/8210
- Branch: `TT-17123-poc-api-to-mcp-v2-part-1`.
- Part 2 patches the derivation helper for non-object JSON request bodies.
- Part 3 consumes the marker to synthesize the runtime adapter and expose the MCP proxy path.
- Technical spec: `TT-17123-rest-as-mcp-technical-spec.md`.
