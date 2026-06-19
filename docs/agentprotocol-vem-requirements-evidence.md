# Agent Protocol VEM Requirements Evidence

<!-- documents SYS-REQ-107 -->
<!-- documents SW-REQ-027 -->

This document records the agent-protocol VEM registry proof slice. The slice is
limited to `internal/agentprotocol` prefix registration and prefix-based path
classification. It does not claim which gateway components call registration,
API definition synthesis, middleware routing, direct-client blocking, or final
HTTP status behavior.

`SW-REQ-027` decomposes `SYS-REQ-107` for the shared in-process registry used
by MCP/JSON-RPC helper code. Evidence in `internal/agentprotocol/vem_test.go`
covers successful registration and positive classification for registered
prefixes, plus negative classification for unrelated paths.
