# internal/httpctx Requirements Evidence

<!-- documents STK-REQ-020 -->
<!-- documents SYS-REQ-108 -->
<!-- documents SW-REQ-028 -->
<!-- documents SW-REQ-036 -->

This slice covers request-context helper behavior in `internal/httpctx`.
It is limited to typed context value storage and retrieval, JSON-RPC request
metadata, JSON-RPC routing state, VEM visit recording, JSON-RPC routing flags,
self-looping flags, and `internal/service/core` upstream-auth provider context
storage.

It does not claim which gateway middleware writes these values, JSON-RPC body
parsing, upstream authentication execution, authorization decisions, analytics
persistence, network transport behavior, or final HTTP status generation.

`STK-REQ-020` captures the request-handler need for deterministic request-scoped
metadata. `SYS-REQ-108` describes the context-helper behavior expected by
downstream gateway helpers. `SW-REQ-028` owns the implementation in
`internal/httpctx`. `SW-REQ-036` owns the implementation in
`internal/service/core`.

Evidence in `internal/httpctx` tests covers successful typed storage and
retrieval, absent and type-mismatched value handling, JSON-RPC request data,
routing-state storage, routing completion decisions, VEM visit recording with a
nil-state guard, JSON-RPC routing flags, and self-looping flags.

Evidence in `internal/service/core` tests covers replacing a request context,
storing and retrieving an upstream-auth provider, absent-provider retrieval,
type-mismatched provider retrieval, overriding an existing context, and empty
context replacement.
