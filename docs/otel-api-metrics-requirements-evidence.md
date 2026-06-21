<!-- documents STK-REQ-092 SYS-REQ-180 SW-REQ-167 -->

`STK-REQ-092`, `SYS-REQ-180`, and `SW-REQ-167` cover local API metrics
behavior in `internal/otel/apimetrics`.

The executable evidence is `internal/otel/apimetrics/*_test.go`. It covers JSON
configuration decoding, default metric definitions, metric definition
validation, dimension extraction and defaulting, bounded token truncation,
filter compilation and matching, dimension-builder reuse and concurrency,
instrument registry creation and source-need flags, and local counter and
histogram recording for tested request contexts.

This evidence does not claim collector/exporter delivery, OpenTelemetry SDK
provider correctness, gateway middleware admission, full HTTP request lifecycle
behavior, metric backend storage, dashboard visibility, cardinality safety for
arbitrary operator-supplied labels, or final client-visible behavior beyond the
focused API metrics tests.
