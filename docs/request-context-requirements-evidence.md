# Request Context Requirements Evidence

<!-- documents STK-REQ-037 SYS-REQ-125 SW-REQ-112 KI-CTX-SESSION-HASH-OVERRIDE -->

`STK-REQ-037`, `SYS-REQ-125`, and `SW-REQ-112` cover local `ctx/ctx.go`
request context helper behavior.

The executable evidence is `ctx/ctx_test.go`. It covers context key uniqueness,
session and auth token storage/retrieval, nil-session panic behavior,
JSON-compatible session fallback retrieval, API and OAS definition clone
retrieval, error-classification storage, and JSON-RPC/MCP metric getter defaults
and typed values.

`KI-CTX-SESSION-HASH-OVERRIDE` records the confirmed defect where a single
optional `SetSession(..., hashKey)` override is ignored because the helper only
uses the override when more than one variadic value is supplied.

This evidence does not claim gateway middleware admission behavior, downstream
plugin behavior, storage persistence, access-control decisions, or final request
handling.
