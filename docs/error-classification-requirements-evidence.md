# Error Classification Requirements Evidence

<!-- documents SYS-REQ-082 -->
<!-- documents SW-REQ-041 -->

This document records the proof scope for the `internal/errors` diagnostic
classifier.

`SYS-REQ-082` owns gateway observability metadata, including the gateway
diagnostic classification behavior added by this slice: upstream
TLS, connection, DNS, timeout, context, string-fallback, generic, circuit
breaker, no-healthy-upstream, upstream-response, authentication, OAuth,
rate-limit, quota, JWT, basic-auth, request-size, and JSON-validation inputs map
to stable response flags, detail strings, source labels, targets, status fields,
TLS metadata, circuit-breaker state, and template metadata where applicable.

`SW-REQ-041` owns the concrete `internal/errors` classifier implementation:
response-flag string values, `ErrorClassification` construction and builder
chaining, upstream error classification priority, typed gateway error
classification, nil upstream error handling, and nil results for unknown typed
identifiers.

This evidence does not claim reverse-proxy execution, gateway middleware
ordering, access-log emission, analytics persistence, network transport
success, upstream availability, or final HTTP status generation.
