<!-- documents STK-REQ-083 SYS-REQ-171 SW-REQ-158 -->

`STK-REQ-083`, `SYS-REQ-171`, and `SW-REQ-158` cover local HTTP request and
response helper behavior in `internal/httputil`.

The executable evidence is `internal/httputil/request_test.go` and
`internal/httputil/response_test.go`. It covers request transfer-encoding
presence and first non-empty transfer-encoding selection; request scheme
selection from `X-Forwarded-Proto`, TLS state, and non-TLS fallback; configured
CORS preflight marker detection; canned local response status helpers for 413,
411, and 500 responses; and removal of one matching response transfer-encoding
value while preserving non-matching and empty values.

This evidence does not claim full browser CORS policy enforcement, proxy
forwarding behavior, upstream behavior, body streaming, analytics, persistence,
or final client responses.
