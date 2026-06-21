<!-- documents STK-REQ-074 SYS-REQ-162 SW-REQ-149 -->

`STK-REQ-074`, `SYS-REQ-162`, and `SW-REQ-149` cover local gateway API loader
helper behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It covers
domain/listen-path key construction, API count aggregation by domain and listen
path including disabled-domain APIs, and custom middleware function path
prefixing for relative middleware paths.

This evidence does not claim full route generation, middleware execution,
storage initialization, API admission, dashboard or RPC synchronization,
network transport behavior, or final client responses.
