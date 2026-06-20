# Gateway OAuth Client Management Requirements Evidence

<!-- reqproof:component gateway_oauth_client_management -->
<!-- documents STK-REQ-055 SYS-REQ-143 SW-REQ-130 -->

`STK-REQ-055`, `SYS-REQ-143`, and `SW-REQ-130` cover local gateway
OAuth client management helper behavior in `gateway/api.go`.

The evidence scope includes:

- OAuth client storage key construction with the gateway OAuth client prefix
- create-client handler responses for valid API-scoped clients and malformed
  or invalid local inputs
- update-client helper responses that preserve immutable client ID and secret
  values while updating mutable local fields
- rotate-client helper responses that replace the local client secret and keep
  existing client identity fields
- refresh-token invalidation handler responses for missing API parameters,
  missing APIs, and accepted local delete requests

This evidence intentionally does not claim OAuth grant correctness, access-token
or refresh-token cryptographic strength, runtime authentication decisions,
storage durability, Redis availability, distributed propagation, dashboard
behavior, MDCB synchronization, network transport behavior, or final
client-visible authorization behavior.
