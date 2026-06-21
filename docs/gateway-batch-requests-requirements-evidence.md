<!-- reqproof:component gateway_batch_requests -->
<!-- documents STK-REQ-104 SYS-REQ-192 SW-REQ-180 -->

`STK-REQ-104`, `SYS-REQ-192`, and `SW-REQ-180` cover focused gateway batch
request behavior in `gateway/batch_requests.go` and route registration in
`gateway/server.go`.

The proof slice is limited to tested gateway batch request behavior: registering
the `/tyk/batch/` endpoint when batch support is enabled, accepting batch POST
requests, rejecting malformed batch request JSON with an explicit bad-request
response, returning an empty JSON array for an empty batch, constructing safe
relative gateway requests, executing sequential batches with stable response
order, executing manual virtual-endpoint batches, applying tested upstream
certificate and insecure-TLS configuration outcomes, preserving configured
non-canonical header names, and encoding batch replies as JSON.

This evidence does not claim arbitrary upstream transport correctness, complete
TLS policy semantics, proxy behavior, rate-limit or authentication enforcement
inside nested requests, JavaScript VM correctness beyond the tested
`TykBatchRequest` call path, complete route-generation behavior, distributed
behavior, analytics, or final client-visible behavior outside the focused batch
request tests.

Evidence is provided by `gateway/batch_requests_test.go`.
