# Crypto Helpers Requirements Evidence

<!-- documents STK-REQ-041 SYS-REQ-129 SW-REQ-116 -->

`STK-REQ-041`, `SYS-REQ-129`, and `SW-REQ-116` cover local
`internal/crypto` helper behavior and the compatibility hash helper alias in
`pkg/alias/crypto`.

The executable evidence is `internal/crypto/*_test.go` and
`pkg/alias/crypto/crypto_reqproof_test.go`. It covers TLS cipher metadata
mapping and name resolution, hash algorithm selection and key hashing, token
generation and token field parsing, certificate helper classification and
CA-pool updates, public-key PEM helper generation, local AES-CFB
encrypt/decrypt helper outcomes, and alias equivalence for the public hash
helper shim.

This evidence does not claim cryptographic strength, randomness quality, TLS
handshake behavior, certificate trust-store policy, gateway authorization
decisions, upstream/downstream transport security, secret storage, or final
client-visible gateway behavior.
