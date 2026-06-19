# Time Requirements Evidence

<!-- documents SYS-REQ-084 -->
<!-- documents SW-REQ-003 -->

This document records the proof scope expansion for gateway configuration
timing behavior and its `internal/time` software decomposition.

`SYS-REQ-084` covers the gateway-visible timing behavior: readable duration
settings must preserve intended values at serialization, parsing, and
conversion boundaries, including explicit malformed-JSON errors and zero
fallback for invalid shorthand duration strings.

`SW-REQ-003` owns the concrete `internal/time.ReadableDuration` helper methods
that implement the system timing behavior.
