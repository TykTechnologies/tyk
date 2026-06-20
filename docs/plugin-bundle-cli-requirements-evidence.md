# Plugin Bundle CLI Requirements Evidence

<!-- documents STK-REQ-025 SYS-REQ-113 SW-REQ-100 -->

This document records the plugin bundle CLI proof slice. The slice is limited to
local `cli/bundler` package behavior and does not claim gateway-side signature
verification, plugin loading, plugin execution, bundle distribution,
persistence, hot reload, or final gateway request behavior.

`STK-REQ-025` owns the operator need for deterministic local plugin bundle
archive construction, malformed bundle input rejection, and optional local
signature attachment.

`SYS-REQ-113` owns the system-level plugin bundle CLI support contract. Its
evidence covers command registration, default flag wiring, manifest loading,
JSON parse errors, manifest validation for referenced files, middleware hooks,
and drivers, explicit local errors for malformed inputs, checksum calculation
over bundled file bytes, ZIP archive creation with bundled files and an updated
manifest, unsigned bundle output when skip-signing is set, RSA private-key
signing, and verifiable base64 signature storage.

`SW-REQ-100` owns the concrete `cli/bundler/bundler.go` helper behavior. Its
evidence is the focused `cli/bundler/bundler_test.go` suite, including a signed
bundle path that verifies the manifest signature against the corresponding
public key.
