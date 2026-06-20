# Upstream Basic Auth Requirements Evidence

<!-- documents STK-REQ-040 SYS-REQ-128 SW-REQ-115 -->

`STK-REQ-040`, `SYS-REQ-128`, and `SW-REQ-115` cover local
`ee/middleware/upstreambasicauth` middleware helper behavior.

The executable evidence is
`ee/middleware/upstreambasicauth/middleware_reqproof_test.go`. It covers
middleware enablement decisions, APISpec construction, default and custom
upstream authentication header selection, basic-auth provider installation into
request context, encoded basic-auth value construction, and request header
overwrite behavior.

This evidence does not claim upstream request execution, reverse-proxy behavior,
credential validation, secret storage, OAuth behavior, network transport
delivery, or final client-visible gateway behavior.
