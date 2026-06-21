<!-- documents STK-REQ-082 SYS-REQ-170 SW-REQ-157 -->

`STK-REQ-082`, `SYS-REQ-170`, and `SW-REQ-157` cover local HTTP streaming
helper behavior in `internal/httputil`.

The executable evidence is `internal/httputil/streaming_test.go`. It covers
gRPC streaming request classification from `Content-Length: -1` and
`Content-Type: application/grpc`; SSE content-type classification for exact
`text/event-stream` and supported parameter forms; rejection of malformed,
empty, partial, and non-SSE content types; SSE streaming response predicates;
exact WebSocket upgrade classification; aggregate request streaming
classification for gRPC and exact Upgrade inputs; aggregate response streaming
classification for SSE inputs; and non-streaming fallbacks.

The known limitation where `Connection: keep-alive, Upgrade` is not treated as
an upgrade request is tracked as `KI-HTTPUTIL-UPGRADE-CONNECTION-TOKEN`.

This evidence does not claim complete HTTP token-list parsing, reverse-proxy
forwarding behavior, upstream availability, MCP runtime handling, analytics,
persistence, or final client responses.
