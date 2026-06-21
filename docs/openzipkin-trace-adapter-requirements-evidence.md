<!-- documents STK-REQ-089 SYS-REQ-177 SW-REQ-164 -->

`STK-REQ-089`, `SYS-REQ-177`, and `SW-REQ-164` cover local OpenZipkin trace
adapter behavior in `trace/openzipkin`.

The executable evidence is `trace/openzipkin/config_test.go`. It covers
JSON-compatible Zipkin option map decoding, supported sampler selection,
stable adapter naming, local tracer initialization success and local
initialization error paths, supported B3 HTTP header extraction and injection,
and forwarding behavior for the local OpenTracing span facade.

This evidence does not claim trace export delivery, collector connectivity,
runtime sampling correctness beyond local sampler construction, span
propagation through gateway requests, unsupported option value handling,
environment override handling, full gateway tracing setup, or final client
responses.
