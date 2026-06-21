<!-- documents STK-REQ-072 SYS-REQ-160 SW-REQ-147 -->

`STK-REQ-072`, `SYS-REQ-160`, and `SW-REQ-147` cover local user serialization
and endpoint collection helper behavior in `user/session.go`.

The executable evidence is `user/session_test.go` and
`user/serialization_helpers_reqproof_test.go`. It covers FieldLimits,
BasicAuthData, JWTData, and Monitor `IsZero` classification; endpoint collection
length, path ordering, and swapping; endpoint-method collection length,
case-insensitive method-name ordering, swapping, and case-insensitive membership
including absent methods.

This evidence does not claim complete session JSON compatibility, policy merge
behavior, gateway routing, endpoint rate-limit application, persistence
backends, or final client responses.
