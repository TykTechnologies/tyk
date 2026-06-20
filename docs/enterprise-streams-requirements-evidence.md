# Enterprise Streams Requirements Evidence

<!-- documents STK-REQ-039 SYS-REQ-127 SW-REQ-114 -->

`STK-REQ-039`, `SYS-REQ-127`, and `SW-REQ-114` cover local
`ee/middleware/streams` enterprise stream middleware helper behavior.

The executable evidence is `ee/middleware/streams/stream_reqproof_test.go`,
`ee/middleware/streams/stream_test.go`, and
`ee/middleware/streams/bento_log_adapter_test.go`. It covers OAS stream config
extraction, request-scoped variable replacement, HTTP path extraction and
matching, manager analytics fallback behavior, unsafe-component filtering and
allow-listing, Bento structured log translation and malformed-log errors, and
stream start/stop terminal outcomes.

This evidence does not claim external Bento delivery correctness, upstream
authentication behavior, gateway API loading, network transport delivery,
persistence, or final client-visible gateway behavior.
