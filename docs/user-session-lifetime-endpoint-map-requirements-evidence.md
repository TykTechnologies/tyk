<!-- documents STK-REQ-073 SYS-REQ-161 SW-REQ-148 -->

`STK-REQ-073`, `SYS-REQ-161`, and `SW-REQ-148` cover local user session
lifetime and endpoint map helper behavior in `user/session.go`.

The formal model is decomposed into two behavior-specific outputs instead of
one broad terminal helper variable: session lifetime selection and endpoint map
conversion. The aggregate TRUE MC/DC row is witnessed by
`TestUserSessionLifetimeAndEndpointMapHelpers`, which drives both local helper
groups. The behavior-specific FALSE rows remain invariant-violation debt until
they are resolved by real reachability evidence, product KnownIssues, or a
reviewed ReqProof modeling policy for invariant rows.

The executable evidence is `user/session_test.go` and
`user/session_lifetime_endpoint_reqproof_test.go`. It covers legacy session
lifetime fallback, key-expiration comparison when expiration is respected,
global lifetime override, post-expiry delete and retain lifetime paths, endpoint
collection flattening into `method:path` maps, duplicate endpoint overwrite
behavior, endpoint map expansion into sorted endpoint collections, and skipping
malformed endpoint map keys.

This evidence does not claim Redis durability, policy merge behavior, gateway
routing, endpoint rate-limit enforcement, distributed synchronization, or final
client responses.
