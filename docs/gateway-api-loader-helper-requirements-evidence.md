<!-- documents STK-REQ-074 SYS-REQ-162 SW-REQ-149 -->

`STK-REQ-074`, `SYS-REQ-162`, and `SW-REQ-149` cover local gateway API loader
helper behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go` and
`gateway/api_loader_test.go`. It covers domain/listen-path key construction,
API count aggregation by domain and listen path including disabled-domain APIs,
custom middleware function path prefixing for relative middleware paths, API
name normalization for loop lookup, and fuzzy local API matching by API ID,
object ID, and normalized loop name. It also covers local API spec ordering by
listen-path specificity, including parameterized path length handling and tested
custom-domain ordering for empty-domain APIs.

This evidence does not claim full route generation, middleware execution,
storage initialization, API admission, internal proxy dispatch, dashboard or RPC
synchronization, network transport behavior, or final client responses.
