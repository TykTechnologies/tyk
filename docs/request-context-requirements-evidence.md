# Request Context Requirements Evidence

<!-- documents STK-REQ-037 SYS-REQ-125 SW-REQ-112 KI-CTX-SESSION-HASH-OVERRIDE -->

`STK-REQ-037`, `SYS-REQ-125`, and `SW-REQ-112` cover local request context
helper behavior in `ctx/ctx.go` and the gateway package wrapper helpers in
`gateway/api.go`.

The executable evidence is `ctx/ctx_test.go` and `gateway/api_test.go`. The
`ctx` package tests cover context key uniqueness, session and auth token
storage/retrieval, nil-session panic behavior, JSON-compatible session fallback
retrieval, API and OAS definition clone retrieval, error-classification storage,
and JSON-RPC/MCP metric getter defaults and typed values. The gateway tests
cover wrapper storage/retrieval behavior for context data, sessions and auth
tokens, cache options, endpoint tracking flags, request timing, API version
metadata, original/rewrite/internal redirect URLs, request method overrides,
GraphQL request state, loop and throttle counters, explicit limit-check flags,
span attributes, request status, and MCP/JSON-RPC metric dimensions.

`KI-CTX-SESSION-HASH-OVERRIDE` records the confirmed defect where a single
optional `SetSession(..., hashKey)` override is ignored because the helper only
uses the override when more than one variadic value is supplied.

This evidence does not claim gateway middleware admission behavior, downstream
plugin behavior, storage persistence, access-control decisions, caller ordering,
or final request handling.
