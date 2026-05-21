# REST API to MCP Summary

This branch adds REST-as-MCP support to the gateway. Operators can expose an existing REST OAS API as an MCP server by creating an MCP-managed proxy whose upstream URL points at:

```text
tyk://<rest-api-id>__mcp-server
```

The source REST API definition does not need MCP exposure fields, and the gateway does not mutate the source OAS. The MCP proxy is the operator-owned public entrypoint; the generated adapter is gateway-internal.

## How It Works

On reload, the gateway scans loaded MCP-managed proxies for `tyk://...__mcp-server` upstreams. For each unique referenced REST API, it synthesizes one shared internal MCP adapter API with ID `<rest-api-id>__mcp-server`. Multiple same-org MCP proxies can point to the same adapter.

The adapter derives MCP tools from the source REST OAS operations:

- only operations with `operationId` become tools;
- internal and blocked operations are skipped;
- if the source API has an allow-list, only allow-listed operations are exposed;
- path, query, header, and JSON body parameters become tool input schema fields.

At runtime, a client calls the MCP proxy. The proxy handles normal Tyk concerns such as auth, ACL/list filtering, and rate limits, then loops to the internal adapter. The adapter uses the official MCP Go SDK for initialize, tools/list, and tools/call handling. For `tools/call`, it builds an internal REST request from the tool arguments, stamps loop trust with the actual caller proxy ID, and dispatches to the paired REST API handler.

Pairing is tracked as:

- REST API ID to shared adapter API ID;
- REST API ID to the set of allowed MCP proxy API IDs.

This lets several proxies share one adapter while still enforcing caller-specific access rights and rejecting forged or unpaired loop calls.

## Current Scope

V1 is tool-only. The internal derivation model is primitive-aware so resources can be added later without replacing the endpoint-to-MCP catalogue design, but no public resource exposure config is added here.

The SDK owns MCP protocol version and capability negotiation. The adapter advertises tool support, including `tools.listChanged`; proxy-specific initialize metadata is intentionally not part of v1 because the SDK adapter is shared across proxies.
