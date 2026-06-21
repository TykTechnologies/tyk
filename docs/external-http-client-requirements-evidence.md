<!-- documents STK-REQ-094 SYS-REQ-182 SW-REQ-169 -->

`STK-REQ-094`, `SYS-REQ-182`, and `SW-REQ-169` cover local external-service
HTTP client factory behavior in `internal/httpclient`.

The executable evidence is `internal/httpclient/*_test.go`. It covers service
configuration detection and merging, service-specific client constructors,
service timeouts and transport settings, proxy selection and bypass behavior,
mTLS file and certificate-store error handling, mTLS error classification,
certificate-store loading, and JWK fetching through a supplied HTTP client and
parser.

This evidence does not claim network reachability, external service
availability, proxy server behavior, certificate authority trust correctness
beyond the focused tests, production certificate-store persistence, JWK
cryptographic validation, OAuth/JWT protocol correctness, or final
client-visible gateway behavior beyond the focused HTTP client factory tests.
