<!-- documents STK-REQ-076 SYS-REQ-164 SW-REQ-151 -->

`STK-REQ-076`, `SYS-REQ-164`, and `SW-REQ-151` cover local gateway API loader
validation behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It verifies
that `skipSpecBecauseInvalid` skips tested HTTP specs with empty or
space-containing listen paths, skips malformed target URLs, accepts tested valid
target URL inputs, does not apply HTTP listen-path validation to a tested
non-HTTP protocol input, and resolves a tested config-secret target URL before
parsing.

This evidence does not claim full API admission, route generation, middleware
execution, upstream connectivity, distributed synchronization, or final client
responses.
