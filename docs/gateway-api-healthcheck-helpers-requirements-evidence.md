<!-- reqproof:component gateway_api_healthcheck_helpers -->
<!-- documents STK-REQ-064 SYS-REQ-152 SW-REQ-139 -->

`STK-REQ-064`, `SYS-REQ-152`, and `SW-REQ-139` cover local gateway API
health-check helper behavior in `gateway/api_healthcheck.go`: initialization
gating, counter key derivation, enabled counter forwarding, rolling-window
counter recording, request-rate average calculation, truncation, and aggregate
health-value projection.

The proof slice is intentionally local. It does not claim Redis durability,
sample-retention correctness, asynchronous scheduling beyond observable storage
invocation, health endpoint routing, distributed storage availability, or final
client-visible health status.

Evidence is provided by focused gateway API health-check helper tests in
`gateway/api_healthcheck_reqproof_test.go`.
