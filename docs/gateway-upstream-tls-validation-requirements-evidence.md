<!-- reqproof:component gateway_upstream_tls_validation -->
<!-- documents STK-REQ-106 SYS-REQ-194 SW-REQ-182 -->

`STK-REQ-106`, `SYS-REQ-194`, and `SW-REQ-182` cover focused gateway upstream
TLS validation behavior in `gateway/cert.go`.

The proof slice is decomposed into tested public-key pinning and CommonName
helper mechanisms: public-key pin enablement, pinned fingerprint selection from
API and global maps, API pin match acceptance, pin mismatch rejection, API
pinning-disabled fallback and global pin behavior, tested proxy pinning
behavior, and forced CommonName validation for the tested direct and proxied
upstream inputs.

This evidence does not claim complete TLS handshake semantics, certificate
chain policy correctness, arbitrary proxy behavior, downstream client
certificate selection, TLS version or cipher policy, certificate material
storage durability, route generation, authentication enforcement, distributed
synchronization, or final client-visible gateway behavior outside the focused
upstream TLS validation tests.

Evidence is provided by `gateway/cert_test.go` and `gateway/cert_old_test.go`.
