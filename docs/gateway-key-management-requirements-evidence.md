<!-- reqproof:component gateway_key_management -->
<!-- documents STK-REQ-053 SYS-REQ-141 SW-REQ-128 -->

`STK-REQ-053`, `SYS-REQ-141`, and `SW-REQ-128` cover local gateway key
management helper behavior in `gateway/api.go`: basic-auth password hash
algorithm selection and password storage transformation, key add/update request
decoding and error reporting, key detail retrieval with quota remaining
calculation and basic-auth password redaction, and key-list retrieval/filtering
helpers including context-cancellation handling and internal quota/rate key
exclusion.

The proof slice is intentionally local. It does not claim password strength,
credential validity for runtime authentication, middleware request admission,
distributed storage durability, Redis availability, dashboard behavior, MDCB
synchronization, policy engine merge atomicity, or final client-visible gateway
authorization behavior.

Evidence is provided by focused gateway helper tests in
`gateway/api_reqproof_test.go`.
