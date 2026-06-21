<!-- documents STK-REQ-084 SYS-REQ-172 SW-REQ-159 -->

`STK-REQ-084`, `SYS-REQ-172`, and `SW-REQ-159` cover local HTTP mux path
helper behavior in `internal/httputil`.

The executable evidence is `internal/httputil/mux_test.go`. It covers valid
and invalid mux path validation; path regular expression preparation for
plain, anchored, suffix, mux-variable, and wildcard patterns; direct mux
template detection; listen-path stripping for simple and mux-template listen
paths; single path matching for exact, anchored, regular expression,
empty-input, and malformed-regexp inputs; and multi-candidate matching across
successful, non-matching, and malformed candidate sets.

This evidence does not claim gateway API loading, route registration,
middleware authorization, upstream behavior, analytics, persistence, or final
client responses.
