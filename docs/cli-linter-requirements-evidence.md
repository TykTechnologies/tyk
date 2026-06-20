# CLI Linter Requirements Evidence

<!-- documents STK-REQ-027 SYS-REQ-115 SW-REQ-102 -->

`STK-REQ-027`, `SYS-REQ-115`, and `SW-REQ-102` cover only the local
`cli/linter/linter.go` configuration lint helper.

The executable evidence is `cli/linter/linter_test.go`. It uses table-driven
cases for malformed JSON, unsupported Go config decode shapes, unknown fields,
accepted empty/default/legacy/null-object shapes, missing filesystem paths,
host-with-port and malformed-host custom format warnings, invalid enum values,
DNS cache schema failures, and error-override schema failures.

This evidence does not claim complete gateway configuration semantics, gateway
startup behavior, persistence, network binding, analytics, or final
client-visible runtime behavior.
