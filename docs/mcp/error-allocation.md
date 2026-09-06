# Modern MCP Gateway error allocation (TT-18008)

For an unambiguously selected modern protocol, Gateway-owned errors use this
public allocation:

| Code | Meaning |
| --- | --- |
| -33000 | Server failure |
| -33001 | Authentication failure |
| -33002 | Authorization failure |
| -33003 | Quota exceeded |
| -33004 | Rate limit exceeded |
| -33005 | IP rejected |
| -33006 | Upstream failure |

These are explicit allocations, not an arithmetic shift of legacy values.
Structured error classification disambiguates middleware failures sharing an
HTTP status. One selected code is used for the wire response, request context,
logs, and persisted MCP analytics. Legacy HTTP-to-JSON-RPC mappings stay unchanged.

Explicit standard JSON-RPC parse/request/method/parameter/internal errors remain
standard codes. Protocol codes -32020, -32021, and -32022 remain reserved.
Upstream JSON-RPC error responses pass through without Gateway relabeling.
