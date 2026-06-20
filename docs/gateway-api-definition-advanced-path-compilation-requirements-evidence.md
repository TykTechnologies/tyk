<!-- reqproof:component gateway_api_definition_advanced_path_compilation -->
<!-- documents STK-REQ-058 SYS-REQ-146 SW-REQ-133 -->

`STK-REQ-058`, `SYS-REQ-146`, and `SW-REQ-133` cover local gateway API
definition advanced path-compilation helper behavior in `gateway/api_definition.go`:
circuit breaker URLSpec setup, URL rewrite metadata, JSVM-disabled virtual path
gating, Go plugin metadata with a local load attempt, persisted GraphQL metadata,
tracked and untracked endpoint metadata, JSON validation schema loader setup,
internal endpoint metadata, and endpoint rate-limit metadata.

The proof slice is intentionally local. It does not claim circuit-breaker event
delivery, JavaScript execution, Go plugin execution, middleware enforcement,
route matching correctness, upstream behavior, gateway request admission, or
final client-visible behavior.

Evidence is provided by focused gateway API definition advanced path-compilation
tests in `gateway/api_definition_test.go`.
