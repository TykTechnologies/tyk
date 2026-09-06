# Modern native MCP ingress (TT-18011)

Native proxy endpoints support 2026-07-28, 2025-11-25, 2025-06-18 and 2025-03-26.
Synthetic REST-as-MCP endpoints expose only the three 2025 versions. Both ingress
and discovery consume the internal ProtocolSupport interface; TT-18004 can extend
the synthetic implementation after its runtime is upgraded.

Modern POST requests require application/json, matching MCP-Protocol-Version and
params._meta["io.modelcontextprotocol/protocolVersion"], and the required namespaced
clientCapabilities object. Mcp-Method must match the method; Mcp-Name must match
tools/call, prompts/get, and resources/read names/URIs. Multiplicity, header syntax,
and Base64 sentinel encoding are validated. Unknown custom Mcp-Param bindings
remain upstream-owned and are forwarded. No source-header projection is added.

Header violations return HTTP 400 / -32020; required metadata errors return
400 / -32602; unsupported endpoint versions return 400 / -32022 with supported
versions. -32021 remains reserved for missing capabilities; native proxy
upstream-specific capability requirements remain upstream-owned.

Modern GET/DELETE return 405, removed lifecycle methods return method-not-found,
and modern session/resumption headers cannot affect routing. Legacy initialize
negotiation and the headerless 2025-03-26 fallback remain supported. Modern
synthetic requests are rejected before policy effects or SDK execution.
