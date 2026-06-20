# Event Requirements Evidence

<!-- documents SYS-REQ-082 -->
<!-- documents SW-REQ-004 -->
<!-- documents SW-REQ-041 -->
<!-- documents SW-REQ-046 -->

This document records the proof scope expansion into `internal/event`.

`SYS-REQ-082` covers the gateway-observable observability metadata behavior:
event display names, accumulated context events, serializable request snapshots,
structured diagnostic error classifications, and filtered access-log field maps
are preserved for event handlers, analytics, audit flows, access logs, and
error-override consumers.

`SW-REQ-004` owns the concrete `internal/event` helper behavior that implements that system requirement: mapped event string rendering, unmapped raw values, context set/get/add behavior, nil retrieval from untouched contexts, base64 request encoding, and empty snapshots when request encoding fails.

`SW-REQ-041` owns the concrete `internal/errors` diagnostic classifier behavior
that implements the structured classification part of the system requirement:
response-flag string values, chainable classification metadata, upstream error
classification priority, typed gateway error classification, nil upstream error
handling, and nil results for unknown typed identifiers. This evidence does not
claim reverse-proxy execution, gateway middleware ordering, access-log emission,
analytics persistence, network transport success, upstream availability, or
final HTTP status generation.

`SW-REQ-046` owns the concrete `internal/httputil/accesslog.Filter` helper
behavior used to shape access-log field maps: empty allow-list passthrough,
exact case-sensitive key retention, default `prefix` retention, absent-key
omission, and deterministic results. This evidence does not claim request
record construction, access-log emission, template rendering, analytics
persistence, logger behavior, network transport success, or final HTTP status
generation.
