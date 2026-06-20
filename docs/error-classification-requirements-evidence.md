# Error Classification Requirements Evidence

<!-- documents SYS-REQ-082 -->
<!-- documents SW-REQ-041 -->
<!-- documents SW-REQ-066 -->

This document records the proof scope for the `internal/errors` diagnostic
classifier and the `pkg/errpack` typed diagnostic error helpers.

`SYS-REQ-082` owns gateway observability metadata, including the gateway
diagnostic classification behavior added by this slice: upstream
TLS, connection, DNS, timeout, context, string-fallback, generic, circuit
breaker, no-healthy-upstream, upstream-response, authentication, OAuth,
rate-limit, quota, JWT, basic-auth, request-size, and JSON-validation inputs map
to stable response flags, detail strings, source labels, targets, status fields,
TLS metadata, circuit-breaker state, and template metadata where applicable.
The same system requirement also owns typed diagnostic error package metadata
used by validation, model, and OAS helper flows: stable error categories,
messages, predecessor chains, and optional log-level metadata.

`SW-REQ-041` owns the concrete `internal/errors` classifier implementation:
response-flag string values, `ErrorClassification` construction and builder
chaining, upstream error classification priority, typed gateway error
classification, nil upstream error handling, and nil results for unknown typed
identifiers.

`SW-REQ-066` owns the concrete `pkg/errpack` typed diagnostic error helper
implementation: stable domain, application, infrastructure, not-found, unknown,
and broken-invariant classifications; nil-preserving wrapping; predecessor
chaining; formatted domain errors; standard error traversal; and deterministic
log-level fallback behavior.

This evidence does not claim caller selection of error categories,
reverse-proxy execution, gateway middleware ordering, access-log emission,
analytics persistence, logger output behavior, validation policy correctness,
storage lookup behavior, network transport success, upstream availability, or
final HTTP status generation.
