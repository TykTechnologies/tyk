# Request Identity Requirements Evidence

<!-- documents STK-REQ-017 -->
<!-- documents SYS-REQ-105 -->
<!-- documents SW-REQ-023 -->

This document records the request client-IP proof slice. The slice is limited to
`request.RealIP` and does not claim authentication, IP allow/block enforcement,
trusted proxy establishment beyond configured XFF depth selection, non-string
`remote_addr` context values, or concurrent mutation safety for `request.Global`.

`STK-REQ-017` owns the gateway-operator need for stable client IP derivation.
`SYS-REQ-105` owns the request-visible behavior: string context value
precedence, valid `X-Real-IP`, configured-depth `X-Forwarded-For`, `RemoteAddr`
fallback for malformed headers, and empty result for invalid configured depth.
`SW-REQ-023` owns the concrete `request.RealIP` helper implementation.

The evidence in `request/real_ip_test.go` covers context precedence, valid and
invalid `X-Real-IP`, valid and invalid `X-Forwarded-For`, depth 0 through 4,
negative and overlong depth, trimming spaces, empty header fallback, and invalid
selected-header fallback.
