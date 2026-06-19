# Custom Policy Identifier Requirements Evidence

<!-- documents SW-REQ-022 -->
<!-- documents SW-REQ-034 -->

This document records the custom policy identifier proof slice. The slice is
limited to the `pkg/identifier.CustomPolicyId` helper and the `pkg/validator`
wrapper used by policy lookup and configuration validation.

`SW-REQ-022` owns preservation of the identifier string value, empty identifiers
as unset, the accepted non-empty character set, and the explicit
invalid-policy-ID domain error for invalid characters.

The evidence in `pkg/identifier/custom_test.go` covers empty identifiers,
letters, digits, allowed punctuation (`.`, `_`, `-`, `~`), and representative
invalid characters including separators, whitespace, punctuation outside the
allowed set, and non-ASCII input. It does not claim gateway policy loading,
gateway API validation responses, policy Apply behavior, storage lookup
semantics, or policy merge outcomes.

`SW-REQ-034` owns the concrete `pkg/validator` wrapper behavior for custom
policy IDs. Its evidence covers default enforcement of `CustomPolicyId`
validation, explicit unsafe-policy-ID opt-out, validation through struct tags,
domain error formatting for custom-policy-ID tag failures, fail-fast behavior
for validator registration errors, and custom-validator dispatch before struct
validation. It does not claim gateway policy loading, API validation HTTP
responses, policy Apply behavior, storage lookup semantics, policy merge
outcomes, or a standalone runtime interface boundary.
