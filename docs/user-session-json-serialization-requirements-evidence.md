<!-- documents STK-REQ-080 SYS-REQ-168 SW-REQ-155 -->

`STK-REQ-080`, `SYS-REQ-168`, and `SW-REQ-155` cover local user session JSON
serialization behavior in `user/session.go`, `user/custom_policies.go`, and the
associated user data model structs.

The executable evidence is `user/session_test.go` and
`user/custom_policies_test.go`. It covers zero session field omission,
configured field preservation, zero and non-zero time serialization, legacy
all-field session JSON decoding, compact session JSON decoding with default zero
values, empty APILimit omission inside access definitions, empty collection and
disabled smoothing omission, access-definition empty collection omission, MCP
access-control field omission and presence when configured, policy post-expiry
action omission and inclusion, and session post-expiry JSON omission,
inclusion, and round-trip preservation.

This evidence does not claim policy merge behavior, gateway authentication,
persistence backends, runtime quota enforcement, session lifetime expiration
behavior, endpoint limit execution, or final client responses.
