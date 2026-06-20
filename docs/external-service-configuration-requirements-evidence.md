# External Service Configuration Requirements Evidence

<!-- documents STK-REQ-029 SYS-REQ-117 SW-REQ-104 -->

`STK-REQ-029`, `SYS-REQ-117`, and `SW-REQ-104` cover local
`config/external_service.go` external service configuration helper behavior.

The executable evidence is `config/external_service_test.go`. It covers JSON
field preservation for global proxy and service-specific mTLS configuration,
zero and partial configuration shapes, service type constants, certificate
store JSON fields, mTLS validation for disabled, file-based, certificate-store,
CA-only, conflicting, and incomplete configurations, and helper classification
for file-based versus certificate-store inputs.

This evidence does not claim proxy transport behavior, certificate loading, TLS
handshake enforcement, outbound service connectivity,
storage/OAuth/webhook/health/discovery delivery, or final gateway runtime
behavior.
