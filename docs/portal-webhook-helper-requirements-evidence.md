<!-- documents STK-REQ-081 SYS-REQ-169 SW-REQ-156 -->

`STK-REQ-081`, `SYS-REQ-169`, and `SW-REQ-156` cover local portal webhook
helper behavior in `internal/portal`.

The executable evidence is `internal/portal/portal_test.go` and
`internal/portal/portal_output_test.go`. It covers portal API base URL
normalization for plain, slash-terminated, and already suffixed inputs; app list
and app detail fetching from local test portal responses; omission of apps
without webhook URLs; ordered webhook credential projection for tested apps;
Bento `portal_webhook` output construction from YAML; dispatch of generated
messages to matching event-type webhook URLs; direct webhook POST success with
configured headers and body preservation; and explicit errors for non-success
webhook responses.

This evidence does not claim external portal availability, webhook endpoint
durability, Bento runtime completeness, gateway event triggering, persistence,
analytics, network delivery outside local test servers, or final client
responses.
