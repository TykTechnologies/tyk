# Gateway Control API Requirements Evidence

<!-- documents STK-REQ-051 SYS-REQ-139 SW-REQ-126 -->

`STK-REQ-051`, `SYS-REQ-139`, and `SW-REQ-126` cover local gateway
control API helper behavior in `gateway/api.go`.

The evidence scope includes:

- stable control API status helper objects for success and error messages
- JSON response writing for structured objects, pre-encoded byte payloads, and
  method-not-allowed responses
- JSON export response writing for successful downloads and non-success
  delegation to the normal JSON writer
- secure/cache-control header wrapping before control API handler execution
- allowed-method filtering that either invokes the wrapped handler or returns a
  method-not-allowed JSON response
- local API and OAS route-dispatch wrappers for tested GET, POST, PUT, and
  PATCH status/header outcomes, plus OAS export filename and public/private
  response shaping
- tested local reload and group-reload handler status responses, including
  callback scheduling through the gateway reload queue
- organization-scoped API lookup and API ID listing helpers, including fallback
  behavior when no exact organization match exists
- API definition inventory listing and retrieval helpers, including explicit
  MCP inclusion filtering and not-found / old-API-as-OAS error status handling
- OAS inventory list and retrieval helpers, including public-mode Tyk extension
  removal on cloned OAS responses
- API add, update, delete, and local persistence helper outcomes, including
  malformed request handling, API ID mismatch handling, filesystem write status,
  OAS/MCP companion document suffix selection, and delete-file status handling
- OAuth client management helper outcomes, including storage ID construction,
  API-scoped create-client responses, update-client mutable field responses
  that preserve immutable ID/secret values, rotate-client secret replacement,
  and refresh-token invalidation statuses
- static mTLS certificate-binding helper validation for empty bindings,
  existing certificate IDs, organization-prefixed certificate IDs, wrong-org
  IDs, path traversal-shaped IDs, and missing certificates
- new-certificate delta calculation for key update validation
- create-key and update-key control API paths accepting valid static mTLS
  certificate bindings and rejecting invalid new bindings

This evidence intentionally does not claim TLS handshake enforcement, runtime
certificate authentication decisions, upstream TLS validation, certificate
storage durability, reload durability, dashboard behavior, network transport
behavior, OAS schema semantic correctness, or final client-visible behavior
beyond the local control API helper and tested handler responses.
