# Access Log Requirements Evidence

<!-- documents SYS-REQ-082 -->
<!-- documents SW-REQ-046 -->
<!-- documents SW-REQ-049 -->

This document records the proof scope for the local access-log helpers in
`internal/httputil/accesslog`.

`SYS-REQ-082` owns gateway observability metadata preservation for event
handlers, analytics, audit flows, access logs, and error-override consumers.
This slice extends that decomposition only for the local record field assembly
and field-filtering helpers that shape access-log metadata before formatting.

`SW-REQ-046` owns the concrete `accesslog.Filter` implementation: empty
allowed-field configuration returns the original field map, configured filtering
keeps exact case-sensitive allowed keys, the `prefix` field is retained by
default when present, absent allowed keys are omitted, and repeated filtering
over the same inputs returns the same resulting field map.

`SW-REQ-049` owns the concrete `accesslog.Record` field assembly helper:
records start with the `access-log` prefix, request and response inputs are
copied into stable field names, API identity/type metadata is preserved when
provided, API keys are obfuscated or hashed according to configuration, trace
IDs, error-classification metadata, and MCP context fields are copied only when
available, and returned field maps pass through the configured allow-list
filter.

This evidence does not claim access-log emission, template rendering, analytics
persistence, logger behavior, reverse-proxy execution, gateway middleware
ordering, network transport success, upstream availability, or final HTTP
status generation.
