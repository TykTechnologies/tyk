# Crypto Helpers Requirements Evidence

<!-- documents STK-REQ-041 SYS-REQ-129 SW-REQ-116 SW-REQ-122 -->

`STK-REQ-041`, `SYS-REQ-129`, `SW-REQ-116`, and `SW-REQ-122` cover
local `internal/crypto` helper behavior, the compatibility hash helper alias
in `pkg/alias/crypto`, and the local Mashery signature validator helpers in
`signature_validator`.

The executable evidence is `internal/crypto/*_test.go` and
`pkg/alias/crypto/crypto_reqproof_test.go` for `SW-REQ-116`, plus
`signature_validator/*_test.go` for `SW-REQ-122`. It covers TLS cipher
metadata mapping and name resolution, hash algorithm selection and key
hashing, token generation and token field parsing, certificate helper
classification and CA-pool updates, public-key PEM helper generation, local
AES-CFB encrypt/decrypt helper outcomes, alias equivalence for the public hash
helper shim, Mashery SHA-256 and MD5 signature digest construction, supported
and unsupported signature validator initialization, public validator interface
conformance, and configured clock-skew validation outcomes.

This evidence does not claim cryptographic strength, randomness quality, TLS
handshake behavior, certificate trust-store policy, gateway authorization
decisions, request authentication middleware behavior, replay protection policy,
clock synchronization, upstream/downstream transport security, secret storage,
or final client-visible gateway behavior.
