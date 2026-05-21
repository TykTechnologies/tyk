# TT-17123 (part 3 of 3) - REST-as-MCP: gateway trust and streamable flow

## Summary

Land the gateway runtime that turns a REST API marked `server.mcp.enabled: true` into an agent-callable MCP server. This final part synthesizes in-memory adapter specs, rebuilds REST<->proxy pairings, routes streamable HTTP through the official SDK handler, enforces caller-bound trust before REST auth bypass, and validates paired MCP proxy admits.

This ticket includes the review fixes for:

- REST-side auth bypass without skipping downstream/global REST middleware;
- binding trust to the actual proxy that called the synthetic adapter;
- duplicate proxy-target ambiguity during pairing rebuild;
- routing full streamable HTTP (`POST`, `GET`, `DELETE`) to the SDK handler;
- reload-time `tools/list_changed` notifications.

## Description

The final runtime shape has three layers:

- **REST API:** operator-managed OAS API with `x-tyk-api-gateway.server.mcp.enabled: true`. It keeps serving normal REST traffic and remains the chain that MCP `tools/call` traverses.
- **Synthetic adapter:** internal APISpec generated on reload with APIID `<rest-api-id>__mcp-server`. It owns the SDK adapter, derived tools, and the streamable HTTP handler.
- **MCP proxy:** operator-managed OAS APIDef created through `/tyk/mcps`, with upstream `tyk://<rest-api-id>__mcp-server`. It owns agent-facing listen path, auth/rate limits, and observability.

Agents connect to the MCP proxy. The proxy chain runs normally, then the internal `tyk://` dispatch reaches the synthetic adapter. The SDK handler manages MCP initialize, sessions, SSE GET streams, DELETE session close, `tools/list`, and `tools/call`. Tool calls are expanded into REST requests and executed through the paired REST chain with a validated in-process trust descriptor.

## Expected Behaviour

- On reload, every REST API with `server.mcp.enabled: true` gets an internal adapter APISpec with deterministic APIID `<rest-id>__mcp-server`.
- The adapter is internal only; it is not stored as an operator API and is not publicly exposed by listen path.
- `/tyk/mcps` accepts a proxy pointing at `tyk://<rest-id>__mcp-server` only when:
  - the REST API exists;
  - the REST API has `mcp.enabled: true`;
  - proxy and REST API have the same org;
  - no other same-org proxy already targets that adapter.
- Paired REST-as-MCP proxies stay plain reverse proxies. They are not marked `IsMCP()` and do not run the generic gateway JSON-RPC parser themselves.
- Synthetic adapter specs route `POST`, `GET`, and `DELETE` directly to `MCPSDKAdapter.StreamableHTTPHandler(nil)` before gateway JSON-RPC parsing.
- Accept normalization preserves streamable HTTP compatibility by ensuring JSON and `text/event-stream` are acceptable.
- SDK streamable sessions survive across requests and receive `notifications/tools/list_changed` when reload changes derived tools.
- `tools/call` requires the actual proxy caller ID stamped by the `tyk://` proxy path to match the admitted pairing index.
- REST-side auth is bypassed only after `MCPLoopAuthBypass` validates:
  - `trust.RESTAPIID` equals the current REST spec;
  - `trust.ProxyAPIID` equals `gw.mcpPairing.ProxyForREST(restID)`;
  - `trust.AdapterAPIID` equals `gw.mcpPairing.AdapterForREST(restID)`.
- After auth/session quota handling, `MCPLoopAuthRestore` restores normal request status so downstream/global REST middleware, including API-level rate limiting, still runs.
- Regular REST clients without an MCP-loop trust descriptor are unaffected.

## Key Changes

- `gateway/mcp_synthesise_adapter.go`
  - synthesize adapter specs during `loadApps`;
  - derive tools from the source REST OAS;
  - attach or update `MCPSDKAdapter`;
  - rebuild pairing maps atomically;
  - treat duplicate proxy targets as ambiguous and admit no latest-wins pairing.
- `gateway/mw_jsonrpc.go`
  - route synthetic adapter `POST`, `GET`, and `DELETE` directly to the SDK streamable HTTP handler;
  - keep Accept normalization for streamable HTTP.
- `gateway/mcp_synthesise_adapter.go` / SDK call path
  - resolve tool calls through the SDK adapter;
  - read the actual caller proxy APIID from SDK request context;
  - require it to match the admitted REST<->proxy pairing before dispatching to REST.
- `gateway/api_loader.go` / loop path
  - stamp the outbound in-memory request context with the proxy APIID when a REST-as-MCP proxy targets `tyk://<rest-id>__mcp-server`;
  - install `MCPLoopAuthBypass` and `MCPLoopAuthRestore` in the REST chain.
- `gateway/mw_mcp_loop_auth_bypass.go`
  - validate REST ID, proxy ID, and adapter ID against pairing state;
  - install the in-memory loop session;
  - mark the request pre-authorized and temporarily set request status to skip REST credential validation.
- `gateway/mw_mcp_loop_auth_restore.go`
  - restore request status after the auth/session quota band.
- `gateway/mcp_api.go`
  - validate paired REST-as-MCP proxy upstreams at admit time;
  - keep paired proxies as plain reverse proxies instead of classic remote-MCP proxies.
- `gateway/model_apispec.go`
  - add synthetic adapter markers and `MCPSDKAdapter`.

## Test Cases

- `tools/list` on a paired MCP proxy returns tools derived from a three-operation REST OAS.
- `tools/call` executes through the authenticated REST API chain even when direct REST calls without credentials fail.
- JSON object bodies are forwarded as REST JSON objects.
- JSON array whole-body calls are exposed as `body` with schema type `array` and are forwarded as arrays.
- Synthetic adapter `GET` and `DELETE` requests reach the SDK streamable HTTP handler instead of the gateway JSON-RPC parser.
- SDK sessions receive `notifications/tools/list_changed` after a reload changes the REST OAS tool catalogue.
- MCP loop requests into auth-protected REST APIs skip REST credential validation but still continue to downstream/global middleware.
- Adapter tool calls fail if the actual caller proxy does not match `gw.mcpPairing.ProxyForREST(restID)`.
- Duplicate same-org proxies targeting the same adapter produce no admitted pairing during rebuild.
- Cross-org proxy-to-adapter references fail admit.
- Forged or mismatched trust descriptors return 403.
- Normal REST traffic on the source API remains unchanged.

## Acceptance Criteria

- `GOCACHE=/private/tmp/tyk-go-cache go test -count=1 ./gateway -run 'MCP|JSONRPC|Loop|Pairing'` is green.
- `GOCACHE=/private/tmp/tyk-go-cache go test -count=1 ./internal/mcp/adapter ./internal/mcp/pairing ./internal/mcp` remains green after rebasing part 3 onto part 2.
- A REST OAS API with `server.mcp.enabled: true` synthesizes an internal adapter on reload.
- A paired MCP proxy can initialize over streamable HTTP and list/call tools through the gateway path.
- Streamable HTTP `POST`, `GET`, and `DELETE` reach the SDK handler for synthetic adapters.
- Reload-time tool changes can deliver `tools/list_changed` to an initialized session.
- REST auth bypass is caller-bound and validates REST/proxy/adapter IDs.
- Duplicate proxy targets are treated as ambiguous rather than latest-wins.
- No admin API or persisted schema changes are required beyond the fields added in part 1.

## RFC Review Alignment

Part 3 owns the gateway/runtime consequences of the RFC review:

- **REST delete lifecycle:** current code deletes only the source REST API files and leaves a paired REST-as-MCP proxy in storage. The technical spec marks this as a before-GA fix. The safest v1 behaviour is to prevent an orphan by returning a clear conflict when deleting a REST API that still has a paired MCP proxy, unless we explicitly implement cascade deletion.
- **Paired proxy delete path:** REST-as-MCP proxies are `IsMCPManaged()` but not `IsMCP()`, so their persisted OAS file can use the OAS suffix rather than the classic MCP suffix. `/tyk/mcps/{id}` delete must be made suffix-aware so operators can clean up paired proxies through the MCP management surface.
- **Per-tool policy parity:** REST-as-MCP proxies should not silently lose MCP tool filtering, per-tool rate limiting, or allow/block semantics available to remote MCP proxies. Either enforce equivalent controls in the REST-as-MCP flow or explicitly document any v1 limitation. The preferred target is parity.
- **Co-location and tags:** the REST API and MCP proxy must be loaded on the same gateway population because the proxy targets an in-memory synthetic adapter. Creation/update should copy or validate tag constraints where possible, and warn/block if the pair can be routed to different gateway instances.
- **Versioned APIs:** version-aware REST-as-MCP routing needs explicit design and tests. This is tracked as a follow-up unless pulled into v1.
- **Internal `tyk://` URL:** the `tyk://<rest-id>__mcp-server` shape should remain an implementation detail. Operator UX should be "create an MCP proxy for REST API X", not manual authoring of adapter URLs.

## Before-GA Follow-Up Owned Here

- Add a test showing REST API deletion cannot silently orphan a paired MCP proxy.
- Fix `/tyk/mcps/{id}` deletion for REST-as-MCP proxies.
- Add coverage that REST-as-MCP keeps expected middleware/policy behaviour, including agent-side auth/rate limits and any MCP tool policy features we claim are supported.
- Add tag/co-location validation or an explicit creation-time warning path.

## Deferred To Technical Spec / V2

- Versioned API routing policy for base/default versions and header/query/path version identifiers.
- Public admin/UI abstraction that hides the internal adapter URL entirely.
- Dashboard preview and enrichment UI for final MCP tool JSON.

## Manual Validation Performed

These validation assets are intentionally outside the repo and are not committed:

- `/private/tmp/tyk-rest-as-mcp-validation/test_rest_as_mcp_validation.py`
  - starts a local Python upstream with 3 endpoints;
  - creates a protected OAS REST API;
  - creates a REST-as-MCP proxy;
  - validates `initialize`/`tools/list` through `mcp-remote`;
  - validates `tools/call` over streamable HTTP;
  - validates object-body and array whole-body request handling.
- Fresh gateway built from `TT-17123-poc-api-to-mcp-v2-part-3`:
  - `/private/tmp/tyk-rest-as-mcp-validation/tyk-validation`
- Validation result:
  - `pytest -q /private/tmp/tyk-rest-as-mcp-validation/test_rest_as_mcp_validation.py`
  - `3 passed in 9.35s`

Manual Roo-compatible stack created for interactive testing:

- REST API ID: `manual-rest-as-mcp-rest`
- MCP proxy ID: `manual-rest-as-mcp-proxy`
- MCP endpoint: `http://127.0.0.1:8080/manual/mcp/`
- Tools verified: `bulkCreate`, `createOrder`, `getCatalogItem`
- Roo config can use either native streamable HTTP:

```json
{
  "mcpServers": {
    "tyk-rest-as-mcp": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:8080/manual/mcp/",
      "headers": {},
      "alwaysAllow": [],
      "disabled": false
    }
  }
}
```

or the `mcp-remote` stdio bridge:

```json
{
  "mcpServers": {
    "tyk-rest-as-mcp": {
      "command": "npx",
      "args": [
        "-y",
        "--package",
        "mcp-remote",
        "mcp-remote",
        "http://127.0.0.1:8080/manual/mcp/",
        "--allow-http",
        "--transport",
        "http-only"
      ],
      "env": {
        "NO_PROXY": "localhost,127.0.0.1"
      },
      "alwaysAllow": [],
      "disabled": false
    }
  }
}
```

Validation note: in the file-backed manual setup, deleting a REST-as-MCP proxy through `/tyk/mcps/{id}` returned `500` because the delete path looked for the classic `-mcp` filename. The validation harness and manual cleanup use `/tyk/apis/oas/{id}` as a fallback for paired proxies. If `/tyk/mcps/{id}` deletion is required for paired proxies in this stack, track that as a follow-up or add it before merge.

## Related Information

- Parent feature: TT-17123 REST-as-MCP.
- Stack order: part 1 -> part 2 -> part 3.
- Branch: `TT-17123-poc-api-to-mcp-v2-part-3`.
- Commit message used for this part: `[TT-17123] REST-as-MCP part 3: fix gateway trust and streamable flow`.
- Part 1 PR: https://github.com/TykTechnologies/tyk/pull/8210
- Part 2 supplies the SDK adapter, pairing index, body handling fixes, and context helpers this gateway wiring consumes.
- Technical spec: `TT-17123-rest-as-mcp-technical-spec.md`.
