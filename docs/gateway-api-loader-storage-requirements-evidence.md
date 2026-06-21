<!-- documents STK-REQ-075 SYS-REQ-163 SW-REQ-150 -->

`STK-REQ-075`, `SYS-REQ-163`, and `SW-REQ-150` cover local gateway API loader
storage setup behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_test.go`. It verifies that
`prepareStorage` creates the local general stores used by the API loader and
initializes the gateway global session manager with the prepared Redis store.
It also verifies that `configureAuthAndOrgStores` selects Redis, LDAP, and RPC
handler classes for tested authentication and session provider inputs.

This evidence does not claim remote RPC connectivity, LDAP network
authentication, Redis persistence behavior, route generation, middleware
execution, API admission, dashboard or RPC synchronization, or final client
responses.
