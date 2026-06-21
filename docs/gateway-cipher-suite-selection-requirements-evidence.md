<!-- reqproof:component gateway_cipher_suite_selection -->
<!-- documents STK-REQ-107 SYS-REQ-195 SW-REQ-183 -->

`STK-REQ-107`, `SYS-REQ-195`, and `SW-REQ-183` cover focused gateway TLS
cipher-suite selection behavior in `gateway/cert.go`.

The proof slice is limited to tested configured cipher-name resolution and TLS
1.2 gateway request behavior: configured cipher-suite names are resolved to Go
TLS cipher IDs, unresolved cipher names are skipped by the resolver, a client
using one of the configured cipher suites can complete the tested HTTPS request,
and a client restricted to a non-configured cipher suite fails the tested
request with the expected TLS error.

This evidence does not claim complete TLS handshake semantics, TLS version
policy, cipher-suite security policy, behavior for every supported cipher name,
certificate material validation, downstream client certificate selection,
upstream TLS behavior, route generation, authentication enforcement,
distributed synchronization, or final client-visible gateway behavior outside
the focused cipher-suite tests.

Evidence is provided by `gateway/cert_test.go`.
