<!-- documents STK-REQ-068 SYS-REQ-156 SW-REQ-143 -->

`STK-REQ-068`, `SYS-REQ-156`, and `SW-REQ-143` cover local regexp package
behavior in `regexp/*.go`.

The executable evidence is `regexp/regexp_test.go` and
`regexp/keybuilder_test.go`. It covers standard and POSIX compilation, cache-hit
metadata, MustCompile panic behavior for invalid expressions, package-level
Match and MatchString error handling, nil-wrapper defaults, wrapper delegation
for matching, replacement, finding, expansion, splitting, literal quoting,
Longest mode, keyBuilder immutable and unsafe key behavior, cache reset,
disabled-cache direct execution, and oversized key/value direct execution.

This evidence does not claim caller validation policy, endpoint behavior,
persistence outside the in-memory cache, cache eviction timing beyond reset/TTL
configuration, or the Go standard library regexp implementation.
