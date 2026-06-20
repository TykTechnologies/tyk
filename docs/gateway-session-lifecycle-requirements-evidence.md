<!-- reqproof:component gateway_session_lifecycle -->
<!-- documents STK-REQ-052 SYS-REQ-140 SW-REQ-127 -->

`STK-REQ-052`, `SYS-REQ-140`, and `SW-REQ-127` cover local gateway
key/session lifecycle helper behavior in `gateway/api.go`: policy-derived trial
expiry and post-expiry field application, policy application followed by session
persistence, API spec lookup from session access rights, session lifetime
selection across API specs, and API access-right limit normalization entry
handling.

The proof slice is intentionally local. It does not claim policy engine merge
atomicity, middleware request admission, Redis or other storage durability,
quota counter correctness, dashboard behavior, distributed synchronization,
runtime authorization decisions, or final client-visible gateway behavior.

Evidence is provided by focused gateway helper tests in
`gateway/api_reqproof_test.go` and existing gateway lifetime tests in
`gateway/api_test.go`.
