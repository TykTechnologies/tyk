# TT-17123 (part 2 of 3) - REST-as-MCP: adapter helpers, body handling, SDK sessions

## Summary

Add the gateway-free support libraries REST-as-MCP needs before runtime wiring: MCP adapter protocol helpers, upstream-request construction, response recording, SDK-backed streamable HTTP support, a pairing index, and internal request-context carriers. This part also includes the review hardening for whole-body JSON request bodies and stateful SDK sessions.

No gateway routing behaviour changes land in this part; part 3 plugs these helpers into `loadApps`, middleware, pairing rebuild, and proxy routing.

## Description

Part 1 introduced the OAS marker and pure tool derivation. Part 2 adds the implementation substrate that keeps the gateway part small and testable:

- Build REST requests from MCP `tools/call` arguments.
- Capture REST responses and map them back into MCP tool results.
- Maintain an official Go MCP SDK server for derived tools.
- Keep streamable HTTP sessions long-lived enough for `notifications/tools/list_changed`.
- Track admitted REST<->proxy / REST<->adapter pairings.
- Carry internal trust and caller metadata through request contexts.

The review updates addressed two correctness gaps:

- JSON request bodies that are arrays/scalars must be exposed as a single `body` argument with the real schema type, and forwarded as the real JSON value.
- A new streamable HTTP handler per request loses session state, so the adapter must own a long-lived handler by default.

## Expected Behaviour

- Object request bodies with properties keep the existing `body.<field>` argument behaviour.
- Non-object JSON request bodies expose one tool argument named `body` with the actual schema type (`array`, `string`, `number`, `boolean`, or `object`).
- `BuildUpstreamRequest` accepts any JSON-marshalable value for a whole-body `body` argument, including arrays and scalars.
- `internal/mcp/adapter.SDKAdapter` owns one long-lived SDK server and one default streamable HTTP handler.
- `SDKAdapter.StreamableHTTPHandler(nil)` returns the adapter-owned stateful handler with JSON POST responses enabled.
- Explicit non-nil streamable options still create a separate handler for tests or special callers.
- `SDKAdapter.UpdateTools` mutates the long-lived SDK server in place and emits SDK `notifications/tools/list_changed` to initialized sessions.
- Pairing state is managed through a mutex-protected `internal/mcp/pairing.Index`.
- `internal/httpctx` exposes internal-only helpers for:
  - paired-loop trust descriptors;
  - the MCP-loop pre-authorized flag;
  - the proxy API ID that actually called a synthetic adapter.

## Key Changes

- Patch `apidef/oas/mcp_proxy_derive.go`:
  - object-with-properties request bodies flatten into `body.<field>`;
  - array/scalar/empty-object request bodies use a whole-body `body` argument;
  - `inputSchema.properties.body.type` reflects the source schema type.
- Add `internal/mcp/adapter/adapter.go`:
  - JSON-RPC envelope helpers;
  - `BuildUpstreamRequest`;
  - `Recorder`;
  - `ToolResultEnvelope`;
  - JSON response helpers.
- Add `internal/mcp/adapter/sdk.go`:
  - `SDKServerConfig`;
  - `NewSDKServer`;
  - `NewSDKAdapter`;
  - `SDKAdapter.StreamableHTTPHandler`;
  - `SDKAdapter.UpdateTools`;
  - SDK tool-result mapping.
- Add `internal/mcp/pairing`:
  - `Index`;
  - `Lookup`;
  - `AdapterLookup`;
  - `Static`;
  - atomic map replacement through `Set`.
- Extend `internal/httpctx/mcp_loop.go`:
  - `MCPLoopTrust`;
  - `SetMCPLoopFromPairedProxy` / `GetMCPLoopFromPairedProxy`;
  - `SetMCPLoopPreAuthorized` / `IsMCPLoopPreAuthorized`;
  - `SetMCPProxyCallerAPIID` / `GetMCPProxyCallerAPIID`;
  - `ContextWithMCPProxyCallerAPIID` / `MCPProxyCallerAPIIDFromContext`.
- Add the new context key in `ctx/ctx.go`.

## Test Cases

- Derive array, string, number, and boolean JSON request bodies as whole-body `body` args with the correct schema type.
- Preserve flattened `body.<field>` behaviour for JSON object bodies with properties.
- Build upstream requests for path, query, header, object-body fields, and whole-body JSON values.
- Verify whole-body values serialize as arrays, strings, numbers, booleans, and objects without reshaping.
- Verify recorder status/content type/body/truncation behaviour.
- Verify MCP tool-result envelopes preserve REST status and truncation metadata.
- Verify SDK adapter initializes with JSON responses.
- Initialize through `SDKAdapter.StreamableHTTPHandler(nil)`, keep the session open, call `UpdateTools`, and assert `notifications/tools/list_changed` is received.
- Verify `pairing.Index` lookups, snapshots, and atomic map replacement.
- Verify trust descriptor, pre-authorized flag, and proxy-caller context helper round trips.

## Acceptance Criteria

- `GOCACHE=/private/tmp/tyk-go-cache go test -count=1 ./apidef/oas` is green.
- `GOCACHE=/private/tmp/tyk-go-cache go test -count=1 ./internal/mcp/adapter ./internal/mcp/pairing ./internal/mcp` is green.
- `internal/mcp/adapter`, `internal/mcp/pairing`, and `internal/httpctx` do not import `gateway`.
- `BuildUpstreamRequest` supports all locations: `path`, `query`, `header`, `body`, and `body.<field>`.
- Whole-body request construction supports arrays, strings, numbers, booleans, and objects.
- `SDKAdapter.StreamableHTTPHandler(nil)` returns a reusable stateful handler.
- `UpdateTools` emits `tools/list_changed` for initialized streamable HTTP sessions.
- No admin API or persisted schema changes beyond part 1's API-definition fields.
- No gateway runtime routing changes in this part.

## RFC Review Alignment

Part 2 owns the protocol/adapter foundation for several RFC review points:

- **Official MCP SDK:** v1 uses the official Go MCP SDK for server lifecycle, Streamable HTTP handling, initialization, sessions, and `tools/list_changed` notifications.
- **Protocol version:** protocol negotiation should remain SDK/lifecycle owned. We should not expose the implemented MCP protocol version as an operator setting unless compatibility work later requires it.
- **Live catalogue updates:** the only dynamic notification required for v1 is `notifications/tools/list_changed`. If resources are added later, that work should add `notifications/resources/list_changed`.
- **Large responses:** v1 remains bounded-buffer tool output, not full REST response streaming. Progress notifications and resource-link based large-output strategies are follow-up work.
- **Truncation safety:** `_meta.truncated` is useful for clients but insufficient for models. The technical spec marks visible truncation text in `content` as a before-GA correctness fix. This belongs close to `ToolResultEnvelope` / `SDKToolResult` because those helpers own REST recorder to MCP result conversion.

## Before-GA Follow-Up Owned Here

- When `Recorder` truncates a REST response body, the MCP tool result must include a visible warning in `content`, not only `_meta.truncated`.
- Avoid presenting malformed partial JSON as a complete JSON document. Prefer a clear text notice or a wrapper/envelope that makes truncation unambiguous.
- Keep the machine-readable metadata for clients that inspect `_meta`.

## Deferred To Technical Spec / V2

- Progress notifications for long-running upstream calls when the client supplies a `progressToken`.
- True streaming/large-response design, potentially using MCP resources or resource links.
- MCP resources and resource list-change notifications.

## Related Information

- Parent feature: TT-17123 REST-as-MCP.
- Stack order: part 1 -> part 2 -> part 3.
- Branch: `TT-17123-poc-api-to-mcp-v2-part-2`.
- Commit message used for this part: `[TT-17123] REST-as-MCP part 2: fix adapter body handling and streamable sessions`.
- Part 3 uses the SDK adapter as the synthetic adapter's streamable HTTP endpoint and uses the context helpers for caller-bound trust validation.
- Technical spec: `TT-17123-rest-as-mcp-technical-spec.md`.
