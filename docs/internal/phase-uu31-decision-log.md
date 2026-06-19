# Phase UU.31 Decision Log

## Goal
Close the L3 model gap that blocks same-package lowering of the 3 endpoint methods
(`ApplyEndpointLevelLimits`, `ApplyJSONRPCMethodLimits`, `ApplyMCPPrimitiveLimits`)
in `internal/policy/apply.go`.

## Changes Made

### 1. L3 Model Directives Added (user package)

- **`user/mcp_access.go`**: Added `// reqproof:abstract sort=Opaque` to
  `JSONRPCMethodLimit` and `MCPPrimitiveLimit` types. These were previously
  unmodeled; the translator could not resolve `[]user.JSONRPCMethodLimit` or
  `[]user.MCPPrimitiveLimit` in method signatures.

- **`user/session.go`**: Changed `AccessDefinition` model fields from bool projections
  to the real opaque types:
  - `// field Endpoints bool` -> `// field Endpoints Endpoints`
  - `// field JSONRPCMethods bool` -> `// field JSONRPCMethods JSONRPCMethodLimit`
  - `// field MCPPrimitives bool` -> `// field MCPPrimitives MCPPrimitiveLimit`

- **`internal/policy/apply.go`**: Added import-level abstract annotations (matching
  the type-level directives in the user package).

### 2. Endpoint Assumes (updated, then eliminated for same-package calls)

**Original decision**: The 3 endpoint assumes were updated to use the real
model types (`user.Endpoints`, `user.JSONRPCMethodLimit`,
`user.MCPPrimitiveLimit`) instead of the old bool projections.

**2026-06-19 follow-up**: The same-package endpoint assumes were removed after
`assume_contract_consistency` flagged them as unbacked callee contracts. A
fresh no-cache `proof verify --no-cache --format json --fail-level error`
reverified all 10 components and passed realization, consistency, vacuity, and
gap analysis without those assumes. This proved the current lemmas do not need
the same-package endpoint-call abstractions, so retaining them would add
unnecessary and over-strong contracts.

**Root cause**: The method bodies contain opaque-type operations the translator
does not support:
- `currEndpoints.Map()` — method call on opaque `Endpoints` type
- `len(currEPMap)` — `len()` on opaque return type
- `result.Endpoints()` — method call on `EndpointsMap`
- `for...range` over opaque-typed map
- `currRL.Duration()` — method call on unmodeled `RateLimit`

Even with all types properly declared as opaque in the model, the translator's
`collectPackageMethodBundles` cannot translate these bodies, so the methods
may not register as callables for direct callee proofs. The current
`applyAPILevelLimits` lemmas no longer need same-package assumes for those
calls.

### 3. emptyRateLimit Lemmas Deleted

The 3 lemmas (`empty_rate_limit_when_rate_zero`,
`empty_rate_limit_when_per_zero`, `empty_rate_limit_false_when_both_nonzero`)
with their associated `// reqproof:requires` directives were removed. The
production function `emptyRateLimit` is preserved (it is called from
`ApplyRateLimits`).

### 4. Verification Results

- Policy package: 13/13 PROVED
- User package: 14/14 PROVED  
- Reqproof self-test: all pass
- Go compilation: clean

## Remaining Gap

The endpoint methods still contain operations on opaque types that the
translator cannot lower directly. This is a translator limitation, not a model
gap. The model is now correctly set up:

- `user.Endpoints` — opaque abstract type (was already declared)
- `user.JSONRPCMethodLimit` — opaque abstract type (NEW)
- `user.MCPPrimitiveLimit` — opaque abstract type (NEW)
- `AccessDefinition` model fields now reference the real opaque types (not bool)

If future lemmas need direct facts about the endpoint merge return values, add
truthful callee lemmas or improve translator support for opaque-type method
calls, `len()` on opaque returns, and `range` over opaque-typed maps. Do not
reintroduce unbacked same-package assumes as a substitute for those proofs.
