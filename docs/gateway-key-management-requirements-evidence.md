<!-- reqproof:component gateway_key_management -->
<!-- documents STK-REQ-053 SYS-REQ-141 SW-REQ-128 -->

`STK-REQ-053`, `SYS-REQ-141`, and `SW-REQ-128` cover local gateway key
management helper behavior in `gateway/api.go`: basic-auth password hash
algorithm selection and password storage transformation, key create/preview
handler status handling, key add/update request decoding and error reporting,
local add-key storage updates gated by
organization, key detail retrieval with quota remaining
calculation and basic-auth password redaction, and key-list retrieval/filtering
helpers including context-cancellation handling and internal quota/rate key
exclusion. The same local proof slice covers raw and hashed key deletion status
handling with optional quota reset, RPC sorted-set forwarding helpers, tested
key route wrapper status handling, hashed-key policy update status handling,
and organization-key route/helper status handling.

The proof slice is intentionally local. It does not claim password strength,
credential validity for runtime authentication, middleware request admission,
distributed storage durability, Redis availability, dashboard behavior, MDCB
synchronization, policy engine merge atomicity, or final client-visible gateway
authorization behavior.

Evidence is provided by focused gateway helper tests in
`gateway/api_reqproof_test.go`.
