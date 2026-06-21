<!-- reqproof:component gateway_api_spec_lifecycle_helpers -->
<!-- documents STK-REQ-062 SYS-REQ-150 SW-REQ-137 -->

`STK-REQ-062`, `SYS-REQ-150`, and `SW-REQ-137` cover local gateway API
spec lifecycle helper behavior in `gateway/api_definition.go`: forwarding Init
calls to configured auth, health, and organization-session handlers, stopping organization
session manager state, and invoking upstream certificate monitoring cancellation
when configured while no-oping safely when absent.

The proof slice is intentionally local. It does not claim storage backend
correctness, certificate check execution, goroutine scheduling, gateway reload
durability, network behavior, or final client-visible responses.

Evidence is provided by focused gateway API definition helper tests in
`gateway/api_definition_test.go`.
