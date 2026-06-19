# Custom Policy Identifier Requirements Evidence

<!-- documents SW-REQ-022 -->

This document records the `pkg/identifier.CustomPolicyId` proof slice. The slice
is limited to the custom policy identifier helper used by policy lookup and
configuration validation.

`SW-REQ-022` owns preservation of the identifier string value, empty identifiers
as unset, the accepted non-empty character set, and the explicit
invalid-policy-ID domain error for invalid characters.

The evidence in `pkg/identifier/custom_test.go` covers empty identifiers,
letters, digits, allowed punctuation (`.`, `_`, `-`, `~`), and representative
invalid characters including separators, whitespace, punctuation outside the
allowed set, and non-ASCII input. It does not claim gateway policy loading,
gateway API validation responses, policy Apply behavior, storage lookup
semantics, or policy merge outcomes.
