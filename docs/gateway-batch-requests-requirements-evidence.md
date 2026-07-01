<!-- reqproof:component gateway_batch_requests -->
<!-- documents STK-REQ-104 SYS-REQ-192 SW-REQ-180 -->

`STK-REQ-104`, `SYS-REQ-192`, and `SW-REQ-180` cover focused gateway batch
request behavior in `gateway/batch_requests.go` and route registration in
`gateway/server.go`.

The proof slice is decomposed into tested gateway batch request mechanisms:
registering and handling the `/tyk/batch/` endpoint for batch-enabled APIs,
constructing safe relative gateway requests and tested manual absolute
requests, preserving configured non-canonical header names, executing and
collating tested batch responses, executing manual virtual-endpoint batches,
applying tested upstream certificate and insecure-TLS configuration outcomes,
and encoding batch replies as JSON.

This evidence does not claim arbitrary upstream transport correctness, complete
TLS policy semantics, proxy behavior, rate-limit or authentication enforcement
inside nested requests, JavaScript VM correctness beyond the tested
`TykBatchRequest` call path, complete route-generation behavior, distributed
behavior, analytics, or final client-visible behavior outside the focused batch
request tests.

Evidence is provided by `gateway/batch_requests_test.go`.
