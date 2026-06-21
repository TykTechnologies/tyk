<!-- documents STK-REQ-093 SYS-REQ-181 SW-REQ-168 -->

`STK-REQ-093`, `SYS-REQ-181`, and `SW-REQ-168` cover local OpenTelemetry
runtime helper behavior in the root `internal/otel` package.

The executable evidence is `internal/otel/*_test.go`. It covers trace and
metrics configuration defaults and inheritance, runtime-metrics enablement
decisions, metric provider and instrument construction, no-op and active metric
recording paths, configuration-state and reload metrics, registry delegation
flags, intentional panic behavior for invalid test registry definitions, trace
provider initialization fallback, API and gateway resource attributes, API
version attributes, span context wrapping and extraction, trace/span ID
extraction, and trace ID response header insertion.

This evidence does not claim collector/exporter delivery, OpenTelemetry SDK
provider correctness beyond local construction/fallback behavior, metric backend
storage, runtime metric collection completeness, full gateway middleware
admission, full HTTP request lifecycle behavior, trace propagation across
services, dashboard visibility, or final client-visible behavior beyond the
focused root OTEL tests.
