# Rate-Limit Configuration Requirements Evidence

<!-- documents STK-REQ-032 SYS-REQ-120 SW-REQ-107 -->

`STK-REQ-032`, `SYS-REQ-120`, and `SW-REQ-107` cover local
`config/rate_limit.go` rate-limit description helper behavior.

The executable evidence is `config/rate_limit_test.go`. It covers the default
distributed Redis description, transaction versus pipeline wording,
fixed-window precedence, Redis rolling selection, Sentinel selection,
distributed Sentinel selection, and smoothing wording.

This evidence does not claim request throttling, quota enforcement, Redis
connectivity, header emission, or final gateway runtime behavior.
