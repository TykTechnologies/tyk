# MCP Origin validation (TT-18030)

Native MCP and REST-as-MCP proxy endpoints reject invalid or untrusted Origin
headers with plain HTTP 403 before reading the body or applying authentication,
policy, or quotas. Missing Origin and same-origin requests pass.

OAS `server.mcp.trustedOrigins` and Classic `mcp.trusted_origins` accept concrete
HTTP(S) origins. Explicit MCP configuration, including an empty object/list,
takes precedence over CORS. When MCP configuration is absent, concrete origins
from enabled CORS are trusted; wildcard patterns never confer trust.

Scheme, hostname, and default ports are canonicalized. Forwarding headers only
influence the external origin when the immediate peer belongs to Gateway
`http_server_options.trusted_proxy_cidrs`. Invalid trusted forwarding headers
are rejected. Configure only immediate proxies that sanitize or append their own
forwarding values. The last hop determines the external origin.

The settings survive OAS/Classic conversion. Invalid MCP origins and proxy CIDRs
are rejected at configuration creation/load. OAuth issuer behavior is unchanged.
