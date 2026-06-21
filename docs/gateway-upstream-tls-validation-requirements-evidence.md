<!-- reqproof:component gateway_upstream_tls_validation -->
<!-- documents STK-REQ-106 SYS-REQ-194 SW-REQ-182 -->

`STK-REQ-106`, `SYS-REQ-194`, and `SW-REQ-182` cover focused gateway upstream
TLS validation behavior in `gateway/cert.go`.

The proof slice is limited to tested public-key pinning and CommonName helper
behavior: public-key pinning succeeds when a configured API pin matches the
upstream public key, fails when the pin does not match, falls back to normal
verification when API certificate pinning is disabled, applies configured
global pins, validates pins through the tested proxy path, and cooperates with
forced CommonName validation for the tested direct and proxied upstream inputs.

This evidence does not claim complete TLS handshake semantics, certificate
chain policy correctness, arbitrary proxy behavior, downstream client
certificate selection, TLS version or cipher policy, certificate material
storage durability, route generation, authentication enforcement, distributed
synchronization, or final client-visible gateway behavior outside the focused
upstream TLS validation tests.

Evidence is provided by `gateway/cert_test.go` and `gateway/cert_old_test.go`.
