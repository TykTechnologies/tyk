<!-- documents STK-REQ-087 SYS-REQ-175 SW-REQ-162 -->

`STK-REQ-087`, `SYS-REQ-175`, and `SW-REQ-162` cover local Mashery signature
validator behavior in `signature_validator`.

The executable evidence is `signature_validator/hash_test.go` and
`signature_validator/validate_test.go`. It covers stable Mashery SHA256 and MD5
hasher names, deterministic digest construction from token, shared secret, and
timestamp inputs, supported and unsupported hasher initialization, rejection of
missing and incorrect signature attempts, rejection outside allowed clock skew,
and acceptance of current, future-within-skew, and past-within-skew signatures.

This evidence does not claim gateway request admission, token lookup, secret
resolution, API configuration selection, replay protection, constant-time
comparison, behavior before successful validator initialization, full Mashery
protocol compatibility, or final client responses.
