# MCP protocol context and telemetry (TT-18010)

Ingress retains one bounded parsed envelope, raw declarations, effective version,
detection source, and validation outcome. Downstream policy consumes this context
and the request body is restored with its original closer. Numeric request IDs
are decoded without float64 rounding.

The persisted fields are `effective_protocol_version`, `declared_protocol_version`,
and `protocol_version_source`. Sources are `header`, `body`, `header_body`, and
`legacy_fallback`. A session ID alone does not establish a negotiated version:
headerless requests use the supported `2025-03-26` fallback. Initialize's body
protocolVersion remains available for legacy negotiation.

Conflicts retain both raw declarations in request context, leave the effective
version empty, and retain the header (or body when no header exists) as the
analytics declared version. `server/discover` and `subscriptions/listen` have
distinct discovery/subscription classifications; this adds no subscription runtime.

Direct ingress rejections use normal error analytics when recording is enabled.
Pump's additive `jsonrpc_error_code` field carries the final wire error even when
detailed traffic recording is disabled. The exact Pump commit is pinned in go.mod;
a released Pump dependency remains necessary before production release readiness.
