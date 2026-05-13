# Expose a REST API as MCP

This guide shows how to make an existing Tyk-managed REST API callable
by AI agents (Claude Desktop, Cursor, etc.) over the Model Context
Protocol — **without** standing up any translator service. Every
`tools/call` runs through the REST API's full middleware chain, so your
existing auth, rate-limiting, validation, transforms, and plugins all
apply.

## Architecture in 30 seconds

Three runtime objects, two of which you manage:

```
agent ──HTTP──> [ Layer A: MCP Proxy ]   <- you manage
                        │
                        ▼  tyk://<adapter-id>
                [ Layer B: Adapter ]      <- synthesised in-memory
                        │
                        ▼  loop into REST chain
                [ Layer C: REST API ]    <- you manage
                        │
                        ▼
                upstream service
```

- **Layer C — REST API.** Your normal OAS API. Add one OAS marker.
- **Layer B — Adapter.** Synthesised in-memory by the gateway when it
  sees the marker. Internal-only. No storage entry, no admin endpoint.
- **Layer A — MCP Proxy.** A separate OAS APIDef you POST to
  `/tyk/mcps`. Owns the agent-facing listenPath (auth, rate-limit). Its
  `upstream.url` points at the adapter via `tyk://<adapter-id>`.

## Step 1: mark the REST API

Add the `server.mcp` block to the REST API's OAS document:

```yaml
x-tyk-api-gateway:
  info:
    name: orders
    state: { active: true }
  server:
    listenPath: { value: /orders/, strip: true }
    authentication:
      enabled: true
      securitySchemes:
        authToken:
          type: apiKey
          in: header
          name: Authorization
    mcp:
      enabled: true
      # expose: [getOrder, createOrder]   # optional allow-list of operationIds
  upstream:
    url: http://orders.internal:8080
```

**Exposure:**

- Default: every operation with an `operationId` becomes a tool.
- Optional `expose` array: provide a whitelist of sanitised operationIds;
  only operations whose name appears in `expose` are emitted.

Apply the change (`PUT /tyk/apis/oas/<id>`). The gateway emits the
paired adapter on the next reload. No further action on the REST API.

## Step 2: create the MCP proxy

POST a separate OAS APIDef to `/tyk/mcps`:

```yaml
x-tyk-api-gateway:
  info:
    name: orders-mcp-proxy
    state: { active: true }
  server:
    listenPath: { value: /mcp/orders/, strip: true }
    authentication:
      enabled: true
      securitySchemes:
        authToken:
          type: apiKey
          in: header
          name: Authorization
  middleware:
    global:
      rate_limit: { rate: 10, per: 1 }
  upstream:
    url: tyk://<rest-api-id>__mcp-server
```

The `tyk://<rest-api-id>__mcp-server` host is the deterministic
synthetic adapter ID. Note: `/tyk/mcps` is the unified management
endpoint for both classic remote-MCP proxies (which are marked
`IsMCP()` and run their own JSON-RPC chain) and REST-as-MCP proxies
(which are plain reverse-proxies whose upstream loops into a synthetic
adapter). The admit handler distinguishes the two cases by parsing
`upstream.url` and only calls `MarkAsMCP()` on the former. The
gateway's admit-time validator (`validateMCP`) checks that:

1. The named REST API is loaded.
2. It has `server.mcp.enabled: true`.
3. It is in the same OrgID as the proxy.
4. No other proxy in the org already targets the same adapter (1:1).

## Step 3: agent client configuration

Point your agent at the proxy's listen path with a Tyk-issued key.

**Claude Desktop / Cursor (HTTP transport):**

```json
{
  "mcpServers": {
    "orders": {
      "url": "https://gateway.example.com/mcp/orders/",
      "transport": "http",
      "headers": {
        "Authorization": "<tyk-key>"
      }
    }
  }
}
```

The agent issues `initialize`, `tools/list`, `tools/call` JSON-RPC
envelopes. Authentication and rate-limit apply at the proxy. The
adapter answers `initialize` / `ping` / `tools/list` inline; `tools/call`
loops back through the REST API's chain (auth bypassed for the
paired-proxy traffic, see "Security model" below) and the upstream
response is wrapped as an MCP `result.content[]` envelope.

## Rate-limit interactions

Tyk session policies key rate limits on each API the session has
`access_rights` for. Three configurations matter:

- **(a) Stacked.** Grant the session access to both the proxy and the
  REST API. Both per-API rate limits stack — the agent is throttled at
  whichever is tighter.
- **(b) Proxy-only + REST global.** Grant only the proxy. The REST API's
  global rate limit (`x-tyk-api-gateway.middleware.global.rateLimit`)
  applies as a fallback when the per-API session limit is absent.
  Effective limit is `min(proxy, REST global)`.
- **(c) Proxy-only.** Grant only the proxy. No REST global. Only the
  proxy governs.

For most operators, (b) is the right default: proxy controls agent
fairness; REST global protects the upstream from any client.

## Security model

The paired-proxy trust model has two independent enforcement points:

1. **Admit time.** `validateMCP` rejects a proxy whose upstream targets
   an adapter that does not exist, is not MCP-exposed, is in a different
   org, or is already paired with another proxy.
2. **Runtime.** When the adapter dispatches `tools/call` into the REST
   chain via the `tyk://` loop, it stamps a `MCPLoopTrust` descriptor on
   the request. The REST chain's `MCPLoopAuthBypass` middleware reads
   the descriptor and refuses to honour it unless the gateway's
   pairing-index (`gw.mcpPairing`) confirms the named proxy is the
   admitted 1:1 caller for this REST API. Mismatch → 403.

Direct REST clients (with no descriptor) are entirely unaffected;
`MCPLoopAuthBypass` is a no-op for them.

## Rollback

- Removing `server.mcp.enabled: true` from the REST OAS on the next
  reload drops the synthetic adapter. The proxy becomes unhealthy on
  `tools/call` but is otherwise harmless.
- Deleting the MCP proxy via `DELETE /tyk/mcps/<id>` removes the
  agent-facing surface. No effect on the REST API.

Both operations are non-destructive.

## What is intentionally not supported in v1

- **Aggregation** (one proxy fronting many REST APIs). Each REST API
  needs its own proxy in v1; 1:1 invariant is enforced.
- **OAuth 2.1 PKCE on the agent side.** Existing Tyk auth schemes only.
- **Streaming MCP responses (SSE).** Upstream is buffered and returned
  in one shot; responses over 1 MiB are tagged `_meta.truncated: true`.
- **`resources/*` and `prompts/*` derivation.** Tools only.
- **Dashboard UI for the `mcp:` toggle.** Raw OAS edit only.

See the RFC `RFC-API-TO-MCP-V9-three-layer.md` in the repo root for the
full design discussion.
