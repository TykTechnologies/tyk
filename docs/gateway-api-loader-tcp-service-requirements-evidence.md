<!-- documents STK-REQ-103 SYS-REQ-191 SW-REQ-178 -->

`STK-REQ-103`, `SYS-REQ-191`, and `SW-REQ-178` cover focused local gateway API
loader TCP service setup behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It verifies
that `loadTCPService` initializes tested TCP API specs with the selected
authentication, organization, and health stores for default and RPC-backed
provider inputs. It also verifies that a tested TCP listen port different from
the gateway listen port registers a TCP proxy entry and that a tested listen
port equal to the gateway listen port does not create a TCP proxy entry.

This evidence does not claim TCP forwarding correctness, listener startup, TLS
or proxy-protocol behavior, service-discovery dialing, storage backend
correctness, authentication or session semantics, route generation, middleware
execution, distributed synchronization, or final client-visible gateway behavior
outside the focused TCP service loader tests.
