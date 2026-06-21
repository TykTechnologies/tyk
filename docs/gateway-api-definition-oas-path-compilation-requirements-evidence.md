<!-- reqproof:component gateway_api_definition_oas_path_compilation -->
<!-- documents STK-REQ-059 SYS-REQ-147 SW-REQ-134 -->

`STK-REQ-059`, `SYS-REQ-147`, and `SW-REQ-134` cover local gateway API
definition OAS path-compilation helper behavior in `gateway/api_definition.go`:
validate-request and mock-response URLSpec construction, operation lookup,
collapsed candidate grouping, path-parameter restrictiveness ordering, static
path shield records, and OAS path-priority sorting.

The proof slice is intentionally local. It does not claim middleware execution,
request validation correctness, mock response delivery, upstream behavior,
gateway request admission, or final client-visible behavior.

Evidence is provided by focused gateway OAS path-priority and helper tests in
`gateway/mw_oas_validate_request_path_priority_test.go`.
