<!-- documents STK-REQ-100 SYS-REQ-188 SW-REQ-175 -->

`STK-REQ-100`, `SYS-REQ-188`, and `SW-REQ-175` cover focused gateway API
loader auxiliary behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_test.go`. The formal model is
decomposed into GraphQL playground route registration and cloud endpoint
selection, New Relic middleware mounting through repeated `loadHTTPService`
calls on a tested router, aggregate mTLS detection for loaded API specs,
invalid-OAS panic recovery text, organization data-age enforcement when
organization quotas are enabled, and `WithQuotaKey` option application.

This evidence does not claim complete API loading, complete route generation,
full middleware ordering or execution, New Relic agent correctness, upstream
connectivity, GraphQL execution correctness, complete panic-recovery behavior,
mTLS authentication enforcement, organization quota correctness, dashboard or
RPC synchronization, distributed behavior, or final client-visible gateway
behavior outside these focused API-loader auxiliary tests.
