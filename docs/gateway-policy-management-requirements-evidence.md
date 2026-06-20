<!-- reqproof:component gateway_policy_management -->
<!-- documents STK-REQ-054 SYS-REQ-142 SW-REQ-129 -->

`STK-REQ-054`, `SYS-REQ-142`, and `SW-REQ-129` cover local gateway policy
management helper behavior in `gateway/api.go`: loaded-policy lookup and
listing, default and configured policy storage root selection, file-backed
policy add/update request decoding and validation, explicit local error status
handling, POST versus PUT success action selection, and file-backed policy
deletion status handling.

The proof slice is intentionally local. It does not claim policy engine merge
semantics, policy reload propagation, dashboard behavior, distributed
synchronization, storage durability, filesystem permissions beyond returned
helper errors, or final client-visible gateway authorization behavior.

Evidence is provided by focused gateway helper tests in
`gateway/api_reqproof_test.go`.
