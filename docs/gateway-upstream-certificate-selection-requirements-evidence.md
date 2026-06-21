<!-- reqproof:component gateway_upstream_certificate_selection -->
<!-- documents STK-REQ-105 SYS-REQ-193 SW-REQ-181 -->

`STK-REQ-105`, `SYS-REQ-193`, and `SW-REQ-181` cover focused gateway upstream
certificate selection behavior in `gateway/cert.go`.

The proof slice is limited to tested certificate-ID selection and upstream
certificate lookup behavior: empty maps return no certificate ID, wildcard
entries match any host, exact host entries match with or without request ports,
wildcard subdomain entries match with or without request ports, port-specific
entries override less-specific entries, later certificate maps override earlier
maps, unmatched hosts return an empty ID, IPv4 and bracketed IPv6 host-with-port
inputs are handled, and tested upstream mTLS requests can select configured API
upstream certificates when the host match is present.

This evidence does not claim complete mTLS handshake semantics, certificate
material validation, private-key storage durability, certificate pinning,
common-name validation, downstream client certificate selection, TLS version or
cipher policy, proxy behavior, route generation, authentication enforcement,
distributed synchronization, or final client-visible gateway behavior outside
the focused upstream certificate selection tests.

Evidence is provided by `gateway/cert_test.go`.
