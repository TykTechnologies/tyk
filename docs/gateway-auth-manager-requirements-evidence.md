<!-- reqproof:component gateway_key_management -->
<!-- documents SYS-REQ-141 SW-REQ-179 -->

`SW-REQ-179` covers local gateway auth-manager helper behavior in
`gateway/auth_manager.go` under the existing gateway key-management system
requirement `SYS-REQ-141`.

The proof slice is limited to local session-manager mechanics: store
initialization and access, session expiry checks, session update/detail/remove
for tested raw and hashed key paths, cache entry clearing triggered by update
and remove, session key listing, quota raw-key deletion including allowance
scopes, reset-quota log-key obfuscation selection, local token generation, and
HMAC secret formatting.

This evidence does not claim password strength, randomness quality, credential
validity for runtime authentication, middleware request admission, Redis or
other storage backend durability, cross-gateway notification delivery, quota
counter correctness, distributed synchronization, dashboard behavior, policy
engine merge atomicity, or final client-visible gateway authorization behavior.

Evidence is provided by focused gateway package tests in
`gateway/auth_manager_reqproof_test.go`, plus existing local auth-manager tests
for quota obfuscation and allowance-scope raw-key deletion in
`gateway/auth_manager_test.go`.
