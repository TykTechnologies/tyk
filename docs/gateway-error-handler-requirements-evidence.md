<!-- documents STK-REQ-067 SYS-REQ-155 SW-REQ-142 -->

`STK-REQ-067`, `SYS-REQ-155`, and `SW-REQ-142` cover local gateway error
response helper behavior in `gateway/handler_error.go` and
`gateway/mw_jsonrpc_helpers.go`.

The executable evidence is `gateway/handler_error_test.go`,
`gateway/handler_error_jsonrpc_test.go`, `gateway/handler_error_override_test.go`,
the `TestOverrideErrors` coverage in `gateway/gateway_test.go`, and
`gateway/mw_jsonrpc_helpers_test.go`. It covers Tyk error map default and
configured override lookup, template response selection for JSON/XML/SOAP
requests, JSON-RPC error response selection and helper delegation when MCP
JSON-RPC routing state exists, JSON-RPC access-denied helper response writing
with and without routing state, request-side error override response writing
and fallback, direct override body writing, analytics status selection,
access-log status selection, latency invariants, and local metrics/health
recording for exercised paths.

This evidence does not claim route generation, request matching/admission,
authentication correctness beyond tested error triggers, upstream availability,
analytics persistence, log transport, complete middleware ordering, full
JSON-RPC routing/parser/method authorization, or general network transport
behavior.
