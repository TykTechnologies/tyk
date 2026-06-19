# JSON-RPC Error Requirements Evidence

<!-- documents STK-REQ-018 -->
<!-- documents SYS-REQ-106 -->
<!-- documents SW-REQ-024 -->

This document records the JSON-RPC error proof slice. The slice is limited to
`internal/jsonrpc/errors` mapper and writer helpers and does not claim
JSON-RPC method routing, request parsing, middleware authorization decisions,
analytics persistence after the response body is returned, or gateway transport
behavior outside these helpers.

`STK-REQ-018` owns the JSON-RPC client need for stable JSON-RPC 2.0 error
envelopes. `SYS-REQ-106` owns the client-visible behavior: HTTP status mapping,
standard and server-defined JSON-RPC error codes, deterministic fallback codes
for unknown `4xx` and `5xx` statuses, and JSON-RPC 2.0 envelope fields.
`SW-REQ-024` owns the concrete `internal/jsonrpc/errors` mapper and writer
implementation.

The evidence in `internal/jsonrpc/errors/mapper_test.go` covers standard
failure statuses, custom authentication, authorization, rate-limit, and
upstream codes, unknown `4xx` and `5xx` fallbacks, method-not-allowed mapping,
and the successful-status no-error boundary.

The evidence in `internal/jsonrpc/errors/writer_test.go` covers response
status, `application/json` content type, JSON-RPC version, mapped code, message,
HTTP status data, string, numeric, float, and null request IDs, returned body
parity for analytics callers, JSON message escaping, and the generic internal
error fallback when response marshaling fails.
