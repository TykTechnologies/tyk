# REST-as-MCP Tool View Live Test Report

This report covers the live validation performed with these three OAS files:

- `rest-as-mcp-tool-view-source-oas.json`
- `rest-as-mcp-tool-view-proxy-a-oas.json`
- `rest-as-mcp-tool-view-proxy-b-oas.json`

Latest rerun: May 21, 2026, after switching the proxy contract to
`x-tyk-mcp-server.primitives[].source` with explicit `allow:true`.

## Setup

The source REST API was loaded first, then the gateway was reloaded so the REST API was available for paired MCP proxy validation.

Then both MCP proxy OAS definitions were loaded and the gateway was reloaded again. The reload synthesized one shared internal MCP adapter:

```text
rest-tool-view-live__mcp-server
```

Both proxy definitions target that same adapter:

```text
tyk://rest-tool-view-live__mcp-server
```

The MCP client was `mcp-remote` connected to the MCP proxy, with JSON-RPC requests sent through the local stdio bridge. The upstream REST test server echoed the HTTP method, path, and query string after the REST-as-MCP adapter translated the JSON-RPC `tools/call` into a source REST request.

## Expected Source Operations

The source REST OAS defines two eligible operations:

- `listOrders`: `GET /orders`, query parameters `status` and `limit`
- `createOrder`: `POST /orders`, query parameter `customer_id`

These are the canonical source operationIds. Proxy tool views refer to these operationIds.

The proxy-side extension uses `x-tyk-mcp-server.primitives[].source` to select
source operations. These live fixtures use `source.operationId`; the same
contract also supports `source.path` + `source.method` for source operations
that do not have an `operationId`.

## Proxy A Expectations

File: `rest-as-mcp-tool-view-proxy-a-oas.json`

Proxy A explicitly allows only:

```json
[
  {
    "source": {
      "operationId": "createOrder"
    },
    "allow": true
  }
]
```

It aliases the MCP-facing tool name:

```text
createOrder -> create_order
```

Expected `tools/list` observation through `mcp-remote`:

- Exactly one tool is listed.
- Tool name is `create_order`.
- Tool description is `Place a new order for a customer`.
- Input schema contains `customer_id`.
- `customer_id` description is `Unique identifier of the customer placing the order`.
- `listOrders` is not visible.

Expected `tools/call` observation:

The client sends a JSON-RPC MCP request:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "create_order",
    "arguments": {
      "customer_id": "C-123"
    }
  }
}
```

The adapter maps that call back to the canonical `createOrder` source operation and forwards this REST request:

```text
POST /orders?customer_id=C-123
```

The observed upstream echo was:

```json
{"method":"POST","path":"/orders","query":{"customer_id":"C-123"}}
```

## Proxy B Expectations

File: `rest-as-mcp-tool-view-proxy-b-oas.json`

Proxy B explicitly allows only:

```json
[
  {
    "source": {
      "operationId": "listOrders"
    },
    "allow": true
  }
]
```

It does not alias the tool name, so the visible tool remains `listOrders`.

Expected `tools/list` observation through `mcp-remote`:

- Exactly one tool is listed.
- Tool name is `listOrders`.
- Tool description is `List orders`.
- Input schema contains `status` as a string.
- Input schema contains `limit` as an integer.
- `create_order` and `createOrder` are not visible.

Expected `tools/call` observation:

The client sends a JSON-RPC MCP request:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "listOrders",
    "arguments": {
      "status": "open",
      "limit": 25
    }
  }
}
```

The adapter maps that call to the canonical `listOrders` source operation and forwards this REST request:

```text
GET /orders?status=open&limit=25
```

The observed upstream echo was:

```json
{"method":"GET","path":"/orders","query":{"limit":"25","status":"open"}}
```

Query parameter ordering is not significant.

## Negative Check

A hidden tool call was tested through Proxy A using JSON-RPC:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "listOrders",
    "arguments": {
      "status": "open"
    }
  }
}
```

Expected result:

- The call is rejected before the REST upstream is invoked.
- The error names the caller proxy and hidden tool.

Observed error:

```text
tool "listOrders" is not exposed for caller proxy "mcp-tool-view-a"
```

## What This Proves

The three definitions validate these behaviors:

- Multiple MCP proxies can share one synthesized REST adapter.
- `tools/list` is rewritten per caller proxy, not globally.
- MCP clients call tools through JSON-RPC `tools/call`.
- Proxy definitions use `primitives[].source` plus explicit `allow:true` to select visible tools.
- Tool aliases are visible externally but map back to the canonical REST operation before the adapter dispatches the upstream HTTP request.
- Parameter description overrides are visible in the MCP input schema.
- Query parameters are forwarded to the REST upstream.
- A tool hidden from a caller proxy is rejected even though the shared adapter knows about it for another proxy.
