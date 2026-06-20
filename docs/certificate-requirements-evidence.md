# Certificate Requirements Evidence

<!-- documents STK-REQ-023 SYS-REQ-111 SW-REQ-098 -->

This document records the first certificate lifecycle proof slice. The slice is
limited to local `certs` package certificate manager support behavior and does
not claim TLS handshake enforcement, mutual-TLS request authentication,
upstream TLS validation, live MDCB availability, external storage durability,
certificate expiry monitoring, gateway request admission, or final
client-visible behavior.

`STK-REQ-023` owns the stakeholder need for predictable local handling of
configured certificate and public-key material. Its acceptance criteria cover
valid material parsing and storage, malformed or expired material rejection,
and deterministic local list/raw/index/delete/cache/cert-pool behavior.

`SYS-REQ-111` owns the system-level certificate lifecycle support contract. Its
evidence covers certificate manager construction with default and overridden
retry/cache settings, encrypted and unencrypted PEM parsing, stable certificate
and public-key ID derivation, malformed/expired/duplicate/mixed/mismatched
material rejection, private-key encryption before storage, organization-scoped
index behavior, storage-backed and file-backed list behavior, public-key
fingerprint and raw-key helpers, raw material retrieval, delete/cache/storage
mutation behavior, CA pool construction that skips raw public keys, certificate
metadata extraction, and masked certificate ID output.

`SW-REQ-098` owns the concrete `certs/manager.go` helper behavior. Its evidence
is the focused `certs/manager_reqproof_test.go` suite plus the existing package
tests. This evidence does not claim security properties outside this local
helper boundary: no live TLS handshake enforcement, no runtime mTLS request
authentication, no upstream TLS validation, no live MDCB availability, no Redis
or external-storage durability, no certificate expiry monitoring job, and no
gateway request admission or final client-visible behavior.
