<!-- documents STK-REQ-090 SYS-REQ-178 SW-REQ-165 -->

`STK-REQ-090`, `SYS-REQ-178`, and `SW-REQ-165` cover local trace manager
behavior in the root `trace` package.

The executable evidence is `trace/trace_test.go`. It covers service ID context
helpers, global manager enable/disable state, no-op tracer fallback, local
tracer factory registration and reuse, handler wrapping with root-span setup,
span extraction and injection forwarding, log helper forwarding to supplied
loggers and active spans, standard logger output, and local provider selection
for tested names and options.

This evidence does not claim trace export delivery, collector connectivity,
runtime sampling correctness, full gateway trace propagation, final client
responses, configured logger use during `AddTracer`, or close-error propagation
from registered tracers. `KI-TRACE-ADDTRACER-IGNORES-CONFIGURED-LOGGER` tracks
the current product defect where `SetLogger` does not affect `AddTracer`.
`KI-TRACE-CLOSE-IGNORES-TRACER-ERROR` tracks the current product defect where
`Close` ignores errors returned by registered tracer closers.
