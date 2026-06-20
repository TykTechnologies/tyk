# Time Requirements Evidence

<!-- documents SYS-REQ-084 -->
<!-- documents SW-REQ-003 -->
<!-- documents SW-REQ-050 -->

This document records the proof scope expansion for gateway configuration
timing behavior and its readable-duration software decompositions.

`SYS-REQ-084` covers the gateway-visible timing behavior: readable duration
settings must preserve intended values at serialization, parsing, and
conversion boundaries, including explicit malformed-JSON errors and zero
fallback for invalid shorthand duration strings.

`SW-REQ-003` owns the concrete `internal/time.ReadableDuration` helper methods
that implement the system timing behavior.

`SW-REQ-050` owns the `apidef/oas.ReadableDuration` alias boundary: the OAS
configuration model exposes the same internal readable-duration helper without
changing assignability, JSON shorthand serialization, valid/empty/invalid/
malformed JSON parsing behavior, unit conversion results, zero handling, or
deterministic repeated serialization.

This evidence does not claim full OAS conversion, API import, route generation,
request matching, gateway request admission, middleware execution, runtime
timeout enforcement, or final HTTP behavior.
