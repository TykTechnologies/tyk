<!-- documents STK-REQ-080 SYS-REQ-168 SW-REQ-155 -->

`STK-REQ-080`, `SYS-REQ-168`, and `SW-REQ-155` cover local user session JSON
serialization behavior in `user/session.go`, `user/custom_policies.go`, and the
associated user data model structs.

The executable evidence is `user/session_test.go` and
`user/custom_policies_test.go`. The formal model is decomposed into zero-value
omission, configured non-zero value preservation, legacy all-field session JSON
decoding, compact session JSON decoding with default zero values,
access-definition/API-limit/collection/MCP access-control JSON shape behavior,
rate-limit smoothing JSON behavior, and policy/session post-expiry JSON
omission, inclusion, and round-trip preservation.

This evidence does not claim policy merge behavior, gateway authentication,
persistence backends, runtime quota enforcement, session lifetime expiration
behavior, endpoint limit execution, or final client responses.
