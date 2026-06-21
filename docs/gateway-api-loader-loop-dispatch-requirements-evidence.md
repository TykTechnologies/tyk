<!-- documents STK-REQ-101 SYS-REQ-189 SW-REQ-176 -->

`STK-REQ-101`, `SYS-REQ-189`, and `SW-REQ-176` cover focused local gateway API
loader loop-dispatch behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It verifies
that `DummyProxyHandler.ServeHTTP` dispatches tested tyk-scheme self-loop
targets to the current API handler, dispatches tested named API loop targets to
the matching loaded API handler, applies tested `method`, `loop_limit`, and
`check_limits` control parameters, preserves non-control target query
parameters, strips control parameters before dispatch, increments the loop
counter, and returns a local missing-target error when a tested loop target
cannot be detected.

This evidence does not claim URL rewrite rule selection, route generation,
middleware chain correctness, authentication or rate-limit correctness,
upstream connectivity, distributed synchronization, or final client-visible
gateway behavior outside the focused dummy proxy handler tests.
