<!-- documents STK-REQ-086 SYS-REQ-174 SW-REQ-161 -->

`STK-REQ-086`, `SYS-REQ-174`, and `SW-REQ-161` cover local Jaeger trace
adapter behavior in `trace/jaeger`.

The executable evidence is `trace/jaeger/config_test.go`. It covers
JSON-compatible Jaeger option map decoding, stable adapter naming, logger error
forwarding, and successful local tracer initialization for tested disabled
Jaeger options with a service-name override.

This evidence does not claim trace export delivery, collector connectivity,
runtime sampling correctness, span propagation through gateway requests,
unsupported option value handling, environment override handling, full gateway
tracing setup, or final client responses.
`KI-JAEGER-LOAD-UNSUPPORTED-OPTION-PANIC` tracks the current product defect
where unsupported option values can panic during local option loading instead of
returning an error.
