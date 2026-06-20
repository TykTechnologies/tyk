# Access Log Requirements Evidence

<!-- documents SYS-REQ-082 -->
<!-- documents SW-REQ-046 -->

This document records the proof scope for the local access-log field filter in
`internal/httputil/accesslog`.

`SYS-REQ-082` owns gateway observability metadata preservation for event
handlers, analytics, audit flows, access logs, and error-override consumers.
This slice extends that decomposition only for the field-filtering helper that
shapes access-log metadata before formatting.

`SW-REQ-046` owns the concrete `accesslog.Filter` implementation: empty
allowed-field configuration returns the original field map, configured filtering
keeps exact case-sensitive allowed keys, the `prefix` field is retained by
default when present, absent allowed keys are omitted, and repeated filtering
over the same inputs returns the same resulting field map.

This evidence does not claim request record construction, access-log emission,
template rendering, analytics persistence, logger behavior, network transport
success, upstream availability, or final HTTP status generation.
