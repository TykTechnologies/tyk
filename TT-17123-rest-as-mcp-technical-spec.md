# TT-17123 REST-as-MCP Technical Spec

## Status

Draft technical spec derived from `RFC-API-TO-MCP-V9-three-layer.md`, the current stacked implementation, manual validation, and RFC review comments.

This spec supersedes the original RFC where implementation details changed during the PoC, most notably the move to the official MCP Go SDK and full Streamable HTTP routing through the SDK handler.

## Problem

Tyk can proxy remote MCP servers, but operators also need to expose an existing Tyk-managed REST API as an MCP server without deploying a sidecar translator. MCP tool calls must still traverse the REST API's gateway chain so existing REST auth, rate limits, transforms, validation, plugins, analytics, and upstream behaviour remain the source of truth.

## Goals

- Allow an OAS REST API to opt in to MCP exposure with `x-tyk-api-gateway.server.mcp.enabled`.
- Derive an MCP tool catalogue from the REST OAS.
- Expose the catalogue through an operator-managed MCP proxy.
- Use the official MCP Go SDK for lifecycle, Streamable HTTP, sessions, and notifications.
- Route `tools/call` through the existing REST API chain.
- Preserve agent-facing auth/rate-limit controls on the MCP proxy.
- Keep synthetic adapter state in memory; do not add a new persisted resource kind.
- Enforce same-org, one-to-one REST/proxy pairing at admit time and runtime.
- Support real MCP clients over Streamable HTTP, including `POST`, `GET`, and `DELETE`.

## Non-Goals For V1

- Aggregating multiple REST APIs behind one MCP proxy.
- Exposing REST endpoints as MCP resources.
- Full upstream response streaming as tool content.
- Progress notifications for long-running REST calls.
- Dashboard UI for enrichment/preview.
- OAuth 2.1 agent-side authorization redesign.
- Manual operator authoring of synthetic adapter URLs as a public contract.

## Architecture

REST-as-MCP uses three layers.

### Layer C: Source REST API

The source API is an existing operator-managed REST API. It opts in with:

```yaml
x-tyk-api-gateway:
  server:
    mcp:
      enabled: true
      expose:
        - getOrder
        - createOrder
```

The classic APIDef projection is `apidef.MCPExposureConfig`:

- `enabled`: marks the REST API as MCP-callable.
- `expose`: optional allow-list of sanitized operationIds; empty means expose every valid operation.

The REST API is not marked `IsMCP()`. It keeps serving normal REST traffic and remains the execution path for MCP tool calls.

### Layer B: Synthetic MCP Adapter

On reload, the gateway synthesizes an internal APISpec for every REST API with MCP exposure enabled.

Properties:

- APIID: `<rest-api-id>__mcp-server`.
- `Internal: true`.
- Not stored in Redis/files/Dashboard.
- Not visible through `/tyk/apis` or `/tyk/mcps`.
- Owns derived tools and the SDK adapter.
- Routes Streamable HTTP directly to `MCPSDKAdapter.StreamableHTTPHandler(nil)`.

The adapter is rebuilt from the REST API on every reload. It has no persisted tool snapshot, so REST OAS changes become visible after reload.

### Layer A: MCP Proxy

The MCP proxy is an operator-managed OAS APIDef created through `/tyk/mcps`. It owns:

- agent-facing listen path;
- agent-facing authentication;
- agent-facing rate limits and quotas;
- observability metadata;
- the internal upstream target pointing at the synthetic adapter.

For REST-as-MCP proxies, the upstream currently resolves to:

```yaml
upstream:
  url: tyk://<rest-api-id>__mcp-server
```

This URL shape is an internal implementation detail. Product UX should eventually expose "create MCP proxy for REST API X" rather than requiring operators to write the synthetic adapter URL.

## Tool Catalogue Derivation

V1 derives tools from the source REST OAS.

Rules:

- Each exposed operation with a usable `operationId` becomes a tool.
- Internal operations are skipped.
- Optional `server.mcp.expose` allow-lists sanitized operationIds.
- Path/query/header parameters become tool arguments.
- JSON object request bodies with properties flatten into `body.<field>` arguments.
- JSON arrays/scalars/empty objects become a single whole-body `body` argument with the real schema type.
- Whole-body arguments can be arrays, strings, numbers, booleans, or objects.

Operator visibility:

- Missing/invalid/skipped operations must produce derivation warnings.
- V1 should at least log method, path, operation, and reason.
- UI/API preview is a follow-up, but the spec should assume operators need pre-flight visibility.

Collision handling:

- The current flat argument model is acceptable for the PoC but should not rely on last-write-wins.
- Preferred rule: preserve simple names when unambiguous; when names collide, prefix by location: `path_id`, `query_id`, `header_id`, `body_id`.
- Collisions should produce warnings.

Naming and enrichment:

- Raw `operationId` derivation is a default, not the final authoring experience.
- Tool enrichment should live outside the source OAS, because the operator may not own the REST API definition.
- The enrichment layer should allow tool name, title, description, parameter descriptions/examples, annotations, output schema, visibility, and exposure mode overrides.
- This should be modelled as MCP proxy/endpoint config, not by rewriting the source REST OAS.

## MCP SDK And Streamable HTTP

The adapter uses the official MCP Go SDK.

Required behaviour:

- `SDKAdapter` owns one long-lived SDK server.
- `SDKAdapter.StreamableHTTPHandler(nil)` returns the adapter-owned stateful Streamable HTTP handler.
- Default handler options use stateful sessions and JSON POST responses.
- `POST`, `GET`, and `DELETE` for synthetic adapters route directly to the SDK handler before gateway JSON-RPC parsing.
- Gateway keeps `Accept` normalization for Streamable HTTP compatibility.
- Initialized sessions survive across requests.
- `SDKAdapter.UpdateTools` updates the server in place and emits `notifications/tools/list_changed`.

Notifications:

- V1 needs `notifications/tools/list_changed`.
- `notifications/resources/list_changed` is needed only when resources are implemented.
- Protocol version negotiation should remain SDK/lifecycle owned rather than operator-configured.

## Tool Call Execution

For `tools/call`:

1. MCP client calls the MCP proxy.
2. Proxy authentication/rate-limit/session middleware runs normally.
3. Proxy internally targets the synthetic adapter through `tyk://`.
4. The gateway stamps the in-memory request context with the actual proxy APIID.
5. SDK adapter receives `tools/call`.
6. Adapter resolves the derived tool and builds a REST request.
7. Adapter requires the actual caller proxy APIID to match the admitted pairing.
8. Adapter stamps a narrow `MCPLoopTrust` descriptor on the REST request.
9. REST chain receives the request.
10. `MCPLoopAuthBypass` validates REST/proxy/adapter IDs against the pairing index, installs the loop session, and marks the request pre-authorized.
11. REST auth middlewares skip credential validation for the loop request.
12. `MCPLoopAuthRestore` restores normal request status so downstream/global middleware still runs.
13. REST upstream response is recorded and converted to an MCP tool result.

Regular REST clients without the internal trust descriptor are unaffected.

## Pairing And Trust

Pairing maps are rebuilt on every reload:

- `restAPIID -> proxyAPIID`
- `restAPIID -> adapterAPIID`

Admit-time checks for REST-as-MCP proxies:

- source REST API exists;
- source REST API has `server.mcp.enabled: true`;
- source REST API and MCP proxy have the same org;
- no other same-org proxy already targets the same adapter.

Runtime checks:

- trust descriptor REST ID must match the current REST spec;
- trust descriptor proxy ID must match `gw.mcpPairing.ProxyForREST(restID)`;
- trust descriptor adapter ID must match `gw.mcpPairing.AdapterForREST(restID)`;
- SDK request context caller proxy ID must match the admitted proxy pairing.

Duplicate proxy targets are ambiguous. The pairing rebuild must not use latest-wins semantics.

## Admin Lifecycle

### Creating A Pair

V1 creation flow:

1. Operator enables `server.mcp.enabled` on the REST API.
2. Operator creates an MCP proxy through `/tyk/mcps`.
3. Gateway validates the proxy upstream against the loaded REST API and org.
4. Reload creates the synthetic adapter and pairing.

Future UX should hide the internal target and offer "create MCP proxy for this REST API".

### Deleting The MCP Proxy

`DELETE /tyk/mcps/{id}` must work for both classic remote-MCP proxies and REST-as-MCP proxies.

Implementation note:

- REST-as-MCP proxies are MCP-managed but not `IsMCP()`.
- Delete code must be suffix-aware and delete the actual persisted files for paired proxies.
- The current file-backed PoC exposed a bug where paired proxies were stored with the OAS suffix but `/tyk/mcps/{id}` looked for the MCP suffix.

### Deleting The Source REST API

The gateway must not silently leave a paired MCP proxy with a dead internal upstream.

Preferred v1 behaviour:

- If a REST API has a paired MCP proxy, `DELETE /tyk/apis.../{restID}` should return a clear conflict instructing the operator to delete the MCP proxy first.
- This avoids accidental data loss while preventing orphaned storage.

Acceptable alternative:

- Cascade-delete generated REST-as-MCP proxies if product decides the proxy is fully generated/owned by the source API.

Do not ship silent orphaning as intentional behaviour.

## Policy, Auth, And Rate Limits

REST-as-MCP has two policy surfaces:

- MCP proxy: agent-facing authentication, quota, and rate limiting.
- REST API: business/API-side middleware, rate limiting, validation, transformations, plugins, and upstream.

Expected v1 behaviour:

- Existing gateway middleware should run for the proxy and source REST API as described.
- REST credential validation is bypassed only for validated internal MCP loop calls.
- Downstream/global REST middleware still runs after auth bypass.
- Remote-MCP and REST-as-MCP should not silently diverge for MCP tool policy semantics.

Before GA, verify or implement parity for:

- per-consumer tool filtering;
- per-tool allow/block lists;
- per-tool rate limiting;
- analytics/audit metadata for tool calls.

If any of these are not supported in v1, document the limitation explicitly rather than implying parity.

## Deployment Topology And Tags

The REST API, MCP proxy, and synthetic adapter must be present on the same gateway instance or gateway population. The adapter is in memory, so a proxy loaded on a gateway that does not also load the REST API cannot resolve the internal target.

Required behaviour:

- Validate or copy tag/segmentation constraints when creating/updating a REST-as-MCP proxy where possible.
- Warn or block when the REST API and MCP proxy can be deployed to different gateway populations.
- Document the co-location requirement.

## Versioned REST APIs

Versioned APIs need an explicit routing policy.

Open questions:

- If the target ID is a base API, should the adapter route through the default version or require a concrete version?
- How should header/query/path version identifiers be supplied by MCP tool calls?
- Should each version have its own adapter/tool catalogue?

This is a follow-up unless product requires version-aware REST-as-MCP in v1.

## Response Mapping And Truncation

V1 maps REST responses into MCP tool results.

Required behaviour:

- HTTP 2xx/3xx responses become normal MCP tool results.
- HTTP 4xx/5xx responses become MCP tool results with `isError: true`.
- REST status, content type, and truncation metadata remain available in `_meta`.
- If the response body is truncated, the returned `content` must visibly tell the model/user that the response is incomplete.

Do not rely only on `_meta.truncated`; many clients do not pass metadata to the model.

For JSON responses, avoid returning broken partial JSON as if it were complete. Prefer a visible warning and/or wrapper format that makes truncation unambiguous.

## Resources, Streaming, And Progress

Not v1 requirements:

- exposing endpoints as MCP resources;
- `resources/list` / `resources/read`;
- `resources/list_changed`;
- true upstream body streaming as tool output;
- progress notifications for slow upstream calls.

Recommended follow-up:

- Add endpoint-level exposure mode: `tool`, `resource`, or both.
- Use resources for stable, read-only, context-heavy endpoints.
- Add progress notifications when clients supply `_meta.progressToken`.
- Consider resource links for large outputs instead of forcing huge payloads into tool text content.

## Validation Plan

Unit/integration tests:

- OAS derivation for parameters, object bodies, array/scalar bodies, skipped operations, and warnings.
- Adapter upstream request construction for all argument locations.
- SDK initialize, `tools/list`, `tools/call`, streamable `GET`, and session `DELETE`.
- `tools/list_changed` delivery after reload.
- Auth-protected REST API tool calls through the MCP proxy.
- Duplicate proxy target ambiguity.
- Caller-bound pairing failure when the actual proxy does not match.
- REST delete cannot silently orphan a paired MCP proxy.
- `/tyk/mcps/{id}` deletes REST-as-MCP proxies.
- Policy/tool enforcement parity for REST-as-MCP.
- Tag/co-location validation where possible.

Manual validation:

- Run a local gateway.
- Import a three-endpoint REST OAS API.
- Create a paired MCP proxy.
- Validate with `mcp-remote` and a real MCP client such as Roo.
- Verify `tools/list` includes expected tools.
- Verify object body and array whole-body tool calls reach the upstream correctly.

## V1 Before-GA Checklist

- Official SDK-backed Streamable HTTP path is used.
- `tools/list_changed` works for initialized sessions.
- Non-object JSON request bodies work end to end.
- REST auth bypass is caller-bound and pairing-validated.
- Synthetic adapter handles `POST`, `GET`, and `DELETE`.
- Duplicate proxy targets are ambiguous, not latest-wins.
- Truncation is visible in `content`.
- REST source deletion cannot silently orphan the MCP proxy.
- `/tyk/mcps/{id}` deletion works for paired proxies.
- Tool policy parity is verified or explicitly documented.
- Tag/co-location risk is validated or clearly surfaced.

## V2 Roadmap

- Endpoint-level MCP enrichment outside the source OAS.
- Final tool catalogue preview in UI/API.
- MCP resources for read-only context-heavy endpoints.
- Progress notifications for long-running tool calls.
- Better large-response strategy using resources/resource links.
- Version-aware REST-as-MCP routing.
- Public "create MCP proxy from REST API" abstraction hiding internal `tyk://` URLs.
- Aggregating multiple REST APIs behind one MCP proxy.

## References

- Original RFC: `RFC-API-TO-MCP-V9-three-layer.md`
- RFC comment responses: `TT-17123-rfc-comment-responses.md`
- Part 1 Jira draft: `TT-17123-part-1-jira.md`
- Part 2 Jira draft: `TT-17123-part-2-jira.md`
- Part 3 Jira draft: `TT-17123-part-3-jira.md`
- MCP tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP Streamable HTTP transport: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP resources: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
- MCP progress notifications: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress
