# Model Requirements Evidence

<!-- documents SW-REQ-007 -->
<!-- documents SW-REQ-008 -->
<!-- documents SYS-REQ-079 -->
<!-- documents SYS-REQ-080 -->
<!-- documents SYS-REQ-081 -->

This document records the first expansion of the proof scope beyond `internal/policy` into `internal/model`.

`SW-REQ-007` covers policy identity normalization and invalid identifier rejection.

`SW-REQ-008` covers policy-store load, lookup, enumeration, deletion, and explicit miss behavior.

`SYS-REQ-079` covers observable policy collision reporting and non-reporting for same database ID replacements.

`SYS-REQ-080` covers merged API list construction, stable logging fields, classic API appends, and tag filtering.

`SYS-REQ-081` covers RPC alias shapes, event metadata construction, and the mock upstream-auth provider adapter. The RPC shape evidence includes the underlying `apidef/rpc.go` JSON field names used by the `internal/model/rpc.go` aliases.
