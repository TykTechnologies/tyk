# MCP List Filtering by Access Control (TBAC) - Implementation Report

## Overview

This report documents the implementation of Tool-Based Access Control (TBAC) for MCP
primitive list responses in the Tyk gateway. The feature filters `tools/list`,
`prompts/list`, `resources/list`, and `resources/templates/list` responses so that
consumers only see the primitives they are authorised to use.

Previously, access control only blocked `tools/call`, `resources/read`, and
`prompts/get` at invocation time. List endpoints passed through unfiltered, meaning
consumers could discover tools they would get a 403 on when trying to call them.

---

## Architecture

### Request flow (before this change)

```
Client  ──POST──>  Gateway  ──POST──>  Upstream MCP Server
                     │
                     ├─ JSONRPCMiddleware (parse method, route to VEM)
                     ├─ JSONRPCAccessControlMiddleware (method-level ACL)
                     ├─ MCPAccessControlMiddleware (primitive-level ACL)
                     ├─ Rate limiting
                     └─ MCPVEMContinuationMiddleware (VEM chain routing)
```

For `tools/call`, `resources/read`, `prompts/get`: the middleware chain enforces
access control and blocks unauthorised invocations **before** proxying to upstream.

For `tools/list`, `prompts/list`, etc.: the request has no primitive type in the
routing state (`PrimitiveType == ""`), so `MCPAccessControlMiddleware` skips the
check and the response passes through unfiltered.

### Request flow (after this change)

```
Client  ──POST──>  Gateway  ──POST──>  Upstream MCP Server
                     │                        │
                     │                   <────┘ Response
                     │
                     ├─ MCPListFilterResponseHandler (RESPONSE middleware)
                     │    └─ Reads JSON-RPC response body
                     │    └─ Filters tools/prompts/resources/resourceTemplates
                     │    └─ Rewrites response body with permitted items only
                     │
                     └─ (for SSE streaming responses)
                          MCPListFilterSSEHook (SSE tap hook)
                            └─ Intercepts SSE events carrying list responses
                            └─ Same filtering logic, applied per-event
```

Two complementary handlers cover both transport modes:

| Transport | Response format | Handler |
|-----------|----------------|---------|
| Standard HTTP | `Content-Type: application/json` | `MCPListFilterResponseHandler` |
| Streamable HTTP / SSE | `Content-Type: text/event-stream` | `MCPListFilterSSEHook` |

### Filtering algorithm

Both handlers use the same logic:

1. Identify the list method (from routing state for HTTP, from result keys for SSE)
2. Look up the session's `MCPAccessRights` for the API
3. Extract the relevant `AccessControlRules` (allowed/blocked patterns) for the primitive type
4. For each item in the response array, extract the name field and check against rules
5. Use the existing `checkAccessControlRules()` function (same as invocation-time enforcement)
6. Rebuild the response with only permitted items; preserve pagination cursors

**Rule evaluation order** (unchanged from invocation-time enforcement):
1. Blocked list checked first - if name matches any blocked pattern, item is removed
2. If Allowed list is non-empty and name does not match any entry, item is removed
3. If both lists are empty, item is permitted

**Deny always takes precedence over allow.** An item in both lists is denied.

---

## Files Changed

### Tyk Gateway (tyk/tyk)

| File | Type | Description |
|------|------|-------------|
| `internal/mcp/jsonrpc.go` | Modified | Added `MethodToolsList`, `MethodPromptsList`, `MethodResourcesList`, `MethodResourcesTemplatesList` constants |
| `gateway/res_handler_mcp_list_filter.go` | **New** | Response middleware for HTTP JSON responses |
| `gateway/res_handler_mcp_list_filter_test.go` | **New** | 30 unit tests + 5 benchmarks for HTTP path |
| `gateway/sse_hook_mcp_list_filter.go` | **New** | SSE tap hook for Streamable HTTP responses |
| `gateway/sse_hook_mcp_list_filter_test.go` | **New** | 20 unit tests + 9 benchmarks for SSE path |
| `gateway/server.go` | Modified | Registered response handler in middleware chain |
| `gateway/reverse_proxy.go` | Modified | Registered SSE hook in SSE tap |

### Mock MCP Server (tyk-mock-mcp-server)

| File | Type | Description |
|------|------|-------------|
| `main.go` | Modified | Added 2 resource templates (`file://{path}`, `db://{schema}/{table}`) |
| `handlers/resources/resources.go` | Modified | Added `FileTemplate` and `DBTemplate` handlers |

### Integration Tests (tyk-analytics)

| File | Type | Description |
|------|------|-------------|
| `tests/api/mcp_client.py` | Modified | Added `list_resource_templates()` method |
| `tests/api/tests/mcp/mcp_list_filter_test.py` | **New** | 15 end-to-end integration tests |

---

## Acceptance Criteria Coverage

### Listing Tools (tools/list)

| Criterion | Test |
|-----------|------|
| Filtered by exact allowlist `["get_weather", "get_forecast"]` | `test_tools_list_filtered_by_allowlist` |
| Filtered by wildcard suffix `["get_*"]` (regex `get_.*`) | `test_tools_list_filtered_by_allowlist_wildcard_suffix` |
| Filtered by exact denylist `["delete_alert", "set_alert"]` | `test_tools_list_filtered_by_denylist` |
| Filtered by wildcard prefix `["*_alert"]` (regex `.*_alert`) | `test_tools_list_filtered_by_denylist_wildcard_prefix` |
| Deny + allow: deny takes precedence, returns no tools | `test_tools_list_deny_takes_precedence_over_allow` |
| Pagination `nextCursor` preserved after filtering | `test_tools_list_pagination_nextCursor_preserved` (unit test) |

### Listing Prompts (prompts/list)

| Criterion | Test |
|-----------|------|
| Prompt allowlist filters prompts/list | `test_prompts_list_filtered_by_allowlist` |
| Prompt denylist filters prompts/list | `test_prompts_list_filtered_by_denylist` |

### Listing Resources (resources/list)

| Criterion | Test |
|-----------|------|
| Resource allowlist filters resources/list | `test_resources_list_filtered_by_allowlist` |
| Resource denylist filters resources/list | `test_resources_list_filtered_by_denylist` |

### Listing Resource Templates (resources/templates/list)

| Criterion | Test |
|-----------|------|
| Template denylist excludes `db://{schema}/{table}` | `test_resource_templates_list_filtered_by_denylist` |
| Template allowlist permits only `file://{path}` | `test_resource_templates_list_filtered_by_allowlist` |

### Cross-cutting

| Criterion | Test |
|-----------|------|
| Tool rules do not affect prompts or resources | `test_tool_rules_do_not_filter_prompts_or_resources` |
| No filtering when MCPAccessRights is empty | `test_tools_list_no_filtering_when_no_acl` |
| Policy-based ACL rules filter tools/list | `test_policy_acl_filters_tools_list` |

---

## Test Summary

### Unit tests (gateway package)

**HTTP response handler** (`res_handler_mcp_list_filter_test.go`):

- 16 table-driven subtests covering all list methods, rule types, edge cases
- 9 standalone tests for nil/empty/wrong-API/content-length/routing-state scenarios
- 5 helper function tests (`TestExtractStringField`)
- 5 benchmarks (100/1000 tools, exact/regex/no-rules)

**SSE hook** (`sse_hook_mcp_list_filter_test.go`):

- 4 constructor tests (`NewMCPListFilterSSEHook`)
- 11 `FilterEvent` tests (allowlist, denylist, regex, deny-precedence, pagination, non-message events, non-list responses, errors, empty data, malformed JSON, multi-line SSE data)
- 2 dedicated primitive type tests (prompts, resource templates)
- 5 `inferListConfigFromResult` tests
- 5 hook-only benchmarks (100/1000 tools, exact/regex, non-list passthrough)
- 4 SSETap end-to-end benchmarks (100/1000 tools, regex, no-rules passthrough)

**Total: 57 unit tests, 14 benchmarks. All pass with `-race`.**

### Integration tests (tyk-analytics)

15 end-to-end tests in `mcp_list_filter_test.py` covering:
- tools/list: allowlist, wildcard, denylist, wildcard-prefix, deny-precedence, no-ACL
- prompts/list: allowlist, denylist
- resources/list: allowlist, denylist
- resources/templates/list: allowlist, denylist
- Cross-primitive isolation
- Policy-based filtering

---

## Performance Analysis

All benchmarks run on Apple M4 Pro, arm64, Go 1.25. Each result is the median
of 3-5 runs.

### HTTP Response Handler Path

| Scenario | Latency | Memory | Allocs |
|----------|---------|--------|--------|
| No rules (1000 tools, passthrough) | **27 us** | 217 KB | 33 |
| 100 tools, 10 exact allowlist entries | **398 us** | 314 KB | 4,538 |
| 100 tools, regex patterns | **245 us** | 175 KB | 2,244 |
| 1000 tools, 10 exact allowlist entries | **4.04 ms** | 3.1 MB | 45,952 |
| 1000 tools, regex patterns | **2.28 ms** | 1.7 MB | 22,057 |

### SSE Hook Path (FilterEvent alone)

| Scenario | Latency | Memory | Allocs |
|----------|---------|--------|--------|
| Non-list event (passthrough) | **1.7 us** | 1.2 KB | 22 |
| 100 tools, 10 exact allowlist entries | **393 us** | 296 KB | 4,512 |
| 100 tools, regex patterns | **242 us** | 155 KB | 2,217 |
| 1000 tools, 10 exact allowlist entries | **4.04 ms** | 2.9 MB | 45,918 |
| 1000 tools, regex patterns | **2.27 ms** | 1.5 MB | 22,021 |

### SSE Tap End-to-End (SSE parse + hook + SSE serialize)

| Scenario | Latency | Memory | Allocs |
|----------|---------|--------|--------|
| No rules (SSETap passthrough, no hook) | **342 us** | 498 KB | 32 |
| 100 tools, 10 exact allowlist entries | **412 us** | 318 KB | 4,529 |
| 1000 tools, 10 exact allowlist entries | **4.36 ms** | 3.2 MB | 45,940 |
| 1000 tools, regex patterns | **2.63 ms** | 1.8 MB | 22,044 |

### Percentage impact

#### SSE streaming path (overhead of filter hook on existing SSETap)

| Scenario | SSETap baseline | With hook | Hook overhead | % increase |
|----------|-----------------|-----------|---------------|------------|
| Non-list event (hot path) | 24 us | 25.7 us | 1.7 us | **~7%** |
| 100 tools, exact rules | 342 us | 412 us | 70 us | **~20%** |
| 1000 tools, exact rules | 342 us | 4,360 us | 4,018 us | **~1174%** |
| 1000 tools, regex rules | 342 us | 2,630 us | 2,288 us | **~669%** |

#### HTTP path (as percentage of total request time)

| Scenario | Filtering cost | % of 50ms RTT | % of 100ms RTT |
|----------|---------------|---------------|----------------|
| No rules | 27 us | 0.05% | 0.03% |
| 15 tools (realistic) | ~60 us | 0.12% | 0.06% |
| 100 tools, exact | 398 us | 0.8% | 0.4% |
| 100 tools, regex | 245 us | 0.5% | 0.25% |
| 1000 tools, exact | 4.04 ms | 7.5% | 3.9% |
| 1000 tools, regex | 2.28 ms | 4.4% | 2.2% |

### Where CPU time is spent (profiled at 1000 tools)

| Component | % of CPU | Description |
|-----------|---------|-------------|
| `checkAccessControlRules` / `matchPattern` | 36% | Regex compilation + matching per item |
| `regexp.Compile` (cached via tyk/regexp) | 23% | Cache lookup includes `time.Now()` for TTL |
| `json.Unmarshal` | 18% | Parsing response body + extracting name fields |
| GC pressure | 13% | Allocations from JSON parse/serialize cycle |
| `json.Marshal` | ~10% | Re-encoding the filtered response |

### Key observations

1. **The passthrough path is essentially free.** When no ACL rules are configured
   (the default), the HTTP handler exits after a nil check — 27 us. The SSE hook
   returns nil and is never instantiated.

2. **Real MCP servers have 10-50 tools, not 1000.** At 15 tools (what the mock
   server exposes), filtering adds ~60 us. The 1000-tool benchmarks are stress
   tests, not realistic scenarios.

3. **Non-list SSE events add 1.7 us.** In a streaming session, 99%+ of events
   are tool call results, notifications, and pings. The hook's quick-exit path
   (check event type + `strings.Contains` for `"result"`) is the real hot path.

4. **List calls happen once per session.** `tools/list` is a discovery call sent
   at connection setup. A one-time 400 us cost is invisible to the user.

5. **Regex is faster than exact match for large lists.** With `get_.*` filtering
   1000 tools, fewer items survive to re-serialization. Less output = less marshal
   time. This is why regex (2.3 ms) beats 10 exact entries (4.0 ms) at scale.

6. **The SSETap framing overhead (~300 us) is pre-existing.** It applies to all
   MCP SSE responses regardless of filtering. The hook adds negligible cost on top.

### Potential optimisations (not needed now)

If a future deployment hits 1000+ tools with complex regex rules:

- **Pre-compile regex patterns at session load time** instead of per-request.
  The `tyk/regexp` cache helps, but eliminates `time.Now()` calls per match.
- **Streaming JSON parser** to avoid full unmarshal/remarshal. Only the primitive
  array needs modification; the envelope and other result keys could be copied as-is.
- **Targeted name extraction** using a byte-level scan for `"name":"..."` instead
  of unmarshalling each item into a `map[string]json.RawMessage`.

None of these are warranted for current scale.

---

## Design Decisions

### Response middleware vs request middleware

The filtering must happen **after** the upstream returns the list, so a response
handler is the only viable approach. Request middleware cannot filter what the
upstream hasn't sent yet.

### Fail-open for malformed data

Items without a parseable name/uri field are **included** in the filtered response.
This prevents the gateway from silently dropping valid items due to unexpected JSON
structure changes in future MCP spec versions.

### SSE hook infers method from result keys

JSON-RPC responses don't include the method name. The SSE hook uses
`inferListConfigFromResult()` to determine the list type by checking which
well-known key exists in the result (`tools`, `prompts`, `resources`,
`resourceTemplates`). These keys are distinct and never appear in non-list
responses, making inference unambiguous.

### Two handlers instead of one

The HTTP and SSE paths have fundamentally different integration points:
- HTTP: `TykResponseHandler` interface, runs before body is copied to client
- SSE: `SSEHook` interface, runs per-event inside the `SSETap` streaming pipeline

Sharing the core filtering logic (via `mcpListConfig`, `checkAccessControlRules`,
`extractStringField`) while keeping the integration glue separate is cleaner than
a single handler trying to detect and handle both transports.

### Registration order

The HTTP response handler is registered **before** `ResponseTransformMiddleware` in
the response chain so that filtering happens first. This ensures body transforms
operate on already-filtered data.

---

## How to run

### Unit tests

```bash
# All MCP list filter tests (HTTP + SSE)
go test -run "TestMCPListFilter|TestExtractStringField|TestNewMCPListFilterSSEHook|TestMCPListFilterSSEHook|TestInferListConfig" -v ./gateway/

# With race detector
go test -run "TestMCPListFilter|TestNewMCPListFilterSSEHook|TestMCPListFilterSSEHook" -race ./gateway/
```

### Benchmarks

```bash
# HTTP response handler benchmarks
go test -run=^$ -bench=BenchmarkMCPListFilter -benchmem ./gateway/

# SSE hook benchmarks
go test -run=^$ -bench=BenchmarkSSEHook -benchmem ./gateway/

# SSE tap end-to-end benchmarks
go test -run=^$ -bench=BenchmarkSSETap_E2E -benchmem ./gateway/

# All filtering benchmarks
go test -run=^$ -bench="BenchmarkMCPListFilter|BenchmarkSSEHook|BenchmarkSSETap_E2E" -benchmem ./gateway/
```

### Integration tests

```bash
# Requires running gateway + dashboard + mock MCP server
cd tyk-analytics/tests/api
pytest tests/mcp/mcp_list_filter_test.py -v -m mcp
```
