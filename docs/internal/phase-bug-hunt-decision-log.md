# Phase: Bug Hunt - Decision Log

**Date:** 2026-05-18
**Scope:** `internal/policy/` — fuzz testing + negative obligation-driven testing
**Branch:** experiment/formal-requirements-policy

---

## Summary

7 fuzz targets written (in `package policy` for unexported function access), 18 negative obligation tests written (in `package policy_test`). 244 tests pass, 6 tests fail — each failure is a discovered bug.

---

## Bugs Found

### Bug 1: `ApplyRateLimits` nil `*APILimit` dereference

- **File:** `internal/policy/apply.go:318`
- **Test:** `TestNegative_MalformedInput_NilAPILimitPointer`
- **Root cause:** `ApplyRateLimits(session, policy, apiLimits)` immediately dereferences `*apiLimits` without a nil guard:
  ```go
  if t.emptyRateLimit(*apiLimits) || ... {
  ```
- **Impact:** Any caller passing a nil `*user.APILimit` causes a panic.
- **Fix:** Add nil check at function entry; return early if nil.

### Bug 2: `Service.Apply` nil `*SessionState` dereference

- **File:** `internal/policy/apply.go:106`
- **Test:** `TestNegative_NilSafety_NilSessionOnApply`
- **Root cause:** `Apply(nil)` immediately accesses `session.MetaData` without a nil guard:
  ```go
  if session.MetaData == nil {
      session.MetaData = make(map[string]interface{})
  }
  ```
- **Impact:** Any caller (e.g. HTTP handler with malformed input) passing nil session causes panic.
- **Fix:** Add nil check at function entry; return error.

### Bug 3: QuotaMax=-1 invariant violated in partition/session-level path

- **File:** `internal/policy/apply.go:605-622` (master policy case) + lines 541-557 (per-API quota partition)
- **Test:** `TestNegative_OverflowSafety_MaxInt64Quota/QuotaMax=-1_with_MaxInt64_renewal`
- **Root cause:** In `applyAPILevelLimits` (line 730), `QuotaMax==-1` resets `QuotaRenewalRate=0`. But in `applyPartitions`, the session-level (master policy) assignment at lines 618-621 blindly copies `policy.QuotaRenewalRate` without checking for the -1 sentinel. The per-API quota partition (lines 541-557) also lacks the reset.
  ```go
  // applyPartitions master-policy case:
  if !usePartitions || policy.Partitions.Quota {
      session.QuotaMax = policy.QuotaMax
      session.QuotaRenewalRate = policy.QuotaRenewalRate  // no -1 check!
  }
  ```
- **Impact:** A policy with `QuotaMax=-1` and `QuotaRenewalRate=MaxInt64` propagates the renewal rate to the session, violating the invariant that "unlimited quota implies zero renewal rate."
- **Fix:** Add `if policy.QuotaMax == -1 { session.QuotaRenewalRate = 0 }` after the assignment in `applyPartitions` (both master-policy and per-API loop).

### Bug 4: Concurrent `Apply` on the same session causes data race

- **File:** `internal/policy/apply.go:68,74,547` (ClearSession writes to session fields)
- **Tests:** `TestNegative_Concurrent_ApplyOnSameSession`, `TestNegative_Concurrent_ClearSessionAndApply`
- **Root cause:** `Apply` and `ClearSession` mutate the session pointer fields (`session.QuotaMax`, `session.Rate`, `session.Per`, `session.MetaData`, `session.AccessRights`, etc.) without any synchronization. When multiple goroutines share the same session object, writes race.
- **Impact:** Data-race UB on concurrent Apply calls (corrupted fields, panics).
- **Fix:** Not a bug per se for the current single-threaded use case, but the concurrency obligation (SYS-REQ-068) requires documenting that Apply is not thread-safe with respect to its session argument, or adding a mutex.

### Bug 5: Apply is not atomic — ClearSession side effects survive errors

- **File:** `internal/policy/apply.go:110-114`
- **Test:** `TestNegative_Atomicity_OrgMismatch`
- **Root cause:** `Apply` calls `ClearSession` first (which zeros session fields), then applies policies. If a policy fails (e.g. org mismatch), the error is returned but the session is already partially zeroed:
  ```go
  if err := t.ClearSession(session); err != nil { ... }
  // ... later, error occurs ...
  return err  // session already modified by ClearSession!
  ```
- **Impact:** A failed Apply leaves the session in a partially-cleared state with Rate=0, Per=0, QuotaMax=0 even though no policies were applied.
- **Fix:** Snapshot session before ClearSession, restore on error; or defer ClearSession to after all policies have been validated.

---

## Tests That Passed (Proving Correctness)

| Test | Obligation |
|---|---|
| FuzzGreaterThanInt64 (86k execs) | overflow_safety |
| FuzzGreaterThanInt (varied) | overflow_safety |
| FuzzSimpleFieldWrite (varied) | malformed_input |
| FuzzApplyAPILevelLimits (178k execs) | overflow_safety |
| FuzzApplyRateLimits (135k execs) | panic_free_input_handling |
| FuzzApplyMain (166k execs) | overflow_safety |
| FuzzApplyPartition (156k execs) | overflow_safety |
| FuzzApplyPerAPI (155k execs) | overflow_safety |
| TestNegative_MalformedInput_NegativeRateLimit | malformed_input |
| TestNegative_MalformedInput_ZeroRateWithQuota | malformed_input |
| TestNegative_MalformedInput_EmptyRequestJSON | malformed_input |
| TestNegative_MalformedInput_NegativeQuota | malformed_input |
| TestNegative_NilSafety_NilStorageOnClearSession | nil_safety |
| TestNegative_NilSafety_NilLogger | nil_safety |
| TestNegative_NilSafety_NilSmoothing | nil_safety |
| TestNegative_NilSafety_NilAccessRights | nil_safety |
| TestNegative_OverflowSafety_MaxInt64Quota (3 of 4 subtests) | overflow_safety |
| TestNegative_OverflowSafety_ApplyRateLimitsEdgeCases (Inf, NaN, MaxFloat64) | overflow_safety |
| TestNegative_OverflowSafety_Multiplication | overflow_safety |
| TestNegative_PanicFree_RandomSession | panic_free_input_handling |
| TestNegative_PanicFree_EmptySlices | panic_free_input_handling |
| TestNegative_Concurrent_DifferentSessionsSameService | concurrent |
| TestNegative_Atomicity_PolicyNotFound | atomicity |
| TestNegative_Atomicity_SecondPolicyFailure | atomicity |

---

## Fuzz Results

| Target | Executions | New Interesting Inputs | Time | Result |
|---|---|---|---|---|
| FuzzGreaterThanInt64 | 86,960 | 1 | 30s | PASS |
| FuzzApplyAPILevelLimits | 178,780 | 5 | 60s | PASS |
| FuzzApplyRateLimits | 135,020 | 2 | 60s | PASS |
| FuzzApplyMain | 166,345 | 1 | 60s | PASS |
| FuzzApplyPartition | 156,770 | 3 | 60s | PASS |
| FuzzApplyPerAPI | 155,195 | 4 | 60s | PASS |
| **Total** | **~879k** | **16** | **5.5min** | **All PASS** |

Key finding: The numerically-intensive functions (`applyAPILevelLimits`, `greaterThanInt64`, `Duration()`) handle all edge cases (MinInt64, MaxInt64, -1 sentinel, NaN, Inf, subnormal float64) without panicking or producing incorrect results. The invariants that Z3 proved about the abstract model hold in the real Go code for the arithmetic functions that Z3 could reach.

---

## DX Issues

1. **Unexported function barrier:** `applyAPILevelLimits`, `simpleFieldWrite`, `applyPartitions` are unexported. Fuzz targets for them must live in `package policy` (not `package policy_test`), which means they build with the production code. This works but is less clean than external tests.

2. **Go fuzz parameter limit:** Only 8 parameters per `f.Fuzz()` call. `applyAPILevelLimits` takes two `AccessDefinition` structs (many fields each). Had to flatten to 8 primitives (4 int64 + 4 float64), leaving many struct fields untested.

3. **Side-effect ordering:** The existing concurrent-obligation test (SYS-REQ-068 in obligation_test.go) uses separate sessions per goroutine and passes. The new tests in `negative_obligation_test.go` use a shared session and detect races. This is a meaningful distinction but easy to miss.

4. **Fuzzer doesn't see the -race detector:** When running `-race` with fuzzing, the fuzzer may miss data races because each invocation uses a single goroutine. Data-race detection requires concurrent usage patterns that fuzzers don't generate naturally.

---

## Testing Gaps

1. **`applyPartitions` internal details:** The partition merge logic for `RestrictedTypes`, `AllowedTypes`, `FieldAccessRights` requires constructing `graphql.Type` and `FieldAccessDefinition` structs — these are large dependency types (from `github.com/TykTechnologies/graphql-go-tools`). Constructing them with random values in fuzz tests would be prohibitively complex.

2. **Request-scoped rate limit decrement:** The actual rate-limit counter decrement (happening per-request in the gateway middleware, not in `internal/policy/`) is not tested here. This is a separate bug surface.

3. **Redis persistence path:** `internal/policy/` is the in-memory apply logic. The RPC loading path (`rpc.go`) is tested for JSON round-trip, but the Redis storage and reload paths are not.

4. **Concurrent ClearSession+Apply on same session:** The -race detector found data races, but the test cannot distinguish between "benign races" (same value written) and "corrupting races" (interleaved struct writes) without additional instrumentation.

---

## Files Created

- `/Users/leonidbugaev/go/src/tyk/internal/policy/fuzz_test.go` — 7 fuzz targets
- `/Users/leonidbugaev/go/src/tyk/internal/policy/negative_obligation_test.go` — 18 negative obligation tests
- This log: `docs/internal/phase-bug-hunt-decision-log.md`
