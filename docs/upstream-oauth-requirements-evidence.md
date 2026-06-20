# Upstream OAuth Requirements Evidence

<!-- documents STK-REQ-049 SYS-REQ-137 SW-REQ-124 -->

`STK-REQ-049`, `SYS-REQ-137`, and `SW-REQ-124` cover local
`ee/middleware/upstreamoauth` middleware helper behavior.

The executable evidence is in the upstream OAuth package tests:

- `ee/middleware/upstreamoauth/middleware_test.go`
- `ee/middleware/upstreamoauth/provider_test.go`
- `ee/middleware/upstreamoauth/provider_comprehensive_test.go`
- `ee/middleware/upstreamoauth/token_cache_test.go`
- `ee/middleware/upstreamoauth/oauth_client_utils_test.go`
- `ee/middleware/upstreamoauth/oauth_context_test.go`

These tests cover middleware enablement decisions, constructor/name behavior,
client-credentials and password provider selection, invalid provider
configuration errors, bearer-token construction, default and custom header
selection, provider installation into request context, token cache hit/miss/error
paths, encrypted cache payload construction and parsing, selected metadata
propagation into request context, external-services HTTP client selection, cache
retry/lock behavior, provider header overwrite behavior, and local OAuth error
event emission.

This evidence does not claim upstream request execution, external OAuth server
correctness, reverse-proxy behavior, credential validity, token cryptographic
strength beyond existing helper use, network transport delivery, or final
client-visible gateway behavior.
