# Obligation Enrichment Decision Log

Date: 2026-05-08
Phase: Obligation Class Expansion and Checklist Enrichment

## Summary

Enriched the Tyk policy engine's obligation system across proof.yaml, all 7 STK-REQs,
and 22 active policy-related SYS-REQs. Added 4 new obligation classes, expanded STK-REQ
obligation checklists, and added obligation_checklist fields to SYS-REQs (previously only
had singular obligation_class).

---

## Decision 1: New obligation classes in proof.yaml

**Context:** The existing 13 obligation classes covered nominal, error, and merge semantics,
but missed several safety-critical domains that the policy engine code explicitly addresses.

**Classes added:**

1. `overflow_safety` — Integer overflow in rate limit and quota calculations. Rate limits
   and quotas use int64 values; comparison and arithmetic operations could silently wrap on
   overflow. This is relevant to STK-REQ-003 (rate limiting), STK-REQ-004 (endpoint limits),
   and all SYS-REQs that perform rate comparisons.

2. `concurrent` with `evidence: [race]` — Policy operations execute in the gateway hot path
   and may be called concurrently from multiple goroutines. The race detector evidence
   requirement ensures concurrent safety is verified by testing. Added primarily to STK-REQ-001
   (Apply is the main concurrent entry point).

3. `atomicity` — STK-REQ-005 explicitly states "strict error atomicity" but the class was
   missing entirely. This is the most critical gap: the requirement's core subject had no
   corresponding obligation class. Atomicity ensures either full success or full failure
   with no partial state.

4. `panic_free_input_handling` — The policy engine must never panic on bad input (nil store
   references, malformed policies). This is directly required by STK-REQ-006 ("never panics
   when the policy store is unavailable") and STK-REQ-005 (error handling must be safe).

**Rationale:** Only classes that directly correspond to actual code behavior in
`internal/policy/apply.go` were added. Classes like `crypto_agility` or `disk_quota`
were considered but rejected as not applicable to the policy engine's domain.

**Evidence file:** proof.yaml lines 17-20.

---

## Decision 2: STK-REQ obligation checklist enrichment

For each STK-REQ, gaps were identified by comparing the existing checklist against the
requirement's description and the actual code behavior.

### STK-REQ-001 (Policy Application via Apply)
- **Added:** `overflow_safety`, `concurrent`, `atomicity`
- **Rationale:** Apply merges rate limits and quotas (overflow_safety), runs in the gateway
  hot path under concurrent access (concurrent), and must not partially merge on error (atomicity).
- **Previous count:** 9 classes
- **New count:** 12 classes

### STK-REQ-002 (ClearSession)
- **Added:** `determinism`, `idempotency`, `malformed_input`, `access_denied`
- **Rationale:** Clearing should produce the same result for the same input (determinism),
  clearing twice = clearing once (idempotency), invalid sessions must be handled
  (malformed_input), and clearing must be authorized (access_denied).
- **Previous count:** 3 classes
- **New count:** 7 classes

### STK-REQ-003 (Rate Limits)
- **Added:** `overflow_safety`, `nil_safety`
- **Rationale:** Rate comparison involves integer arithmetic (overflow_safety), and
  nil session/policy must be handled (nil_safety).
- **Previous count:** 7 classes
- **New count:** 9 classes

### STK-REQ-004 (Endpoint-Level Rate Limits)
- **Added:** `overflow_safety`, `error_handling`, `nil_safety`
- **Rationale:** Endpoint rate calculations (overflow_safety), error cases for endpoint
  merging (error_handling), nil input handling (nil_safety).
- **Previous count:** 6 classes
- **New count:** 9 classes

### STK-REQ-005 (Error Atomicity) — CRITICAL ENRICHMENT
- **Added:** `atomicity`, `determinism`, `nil_safety`, `panic_free_input_handling`
- **Rationale:** This is the KEY gap. The requirement is literally about atomicity but
  `atomicity` was missing from its checklist. Also: error behavior must be deterministic
  (determinism), nil store/input must be safe (nil_safety), never panic on bad input
  (panic_free_input_handling).
- **Previous count:** 4 classes
- **New count:** 8 classes

### STK-REQ-006 (Idle Safety)
- **Added:** `determinism`, `panic_free_input_handling`, `malformed_input`
- **Rationale:** Idle state outputs must be deterministic (determinism), "never panics when
  policy store unavailable" maps directly to panic_free_input_handling, and malformed idle
  state must be handled (malformed_input).
- **Previous count:** 3 classes
- **New count:** 6 classes

### STK-REQ-007 (Performance)
- **Added:** `boundary`, `determinism`, `overflow_safety`
- **Rationale:** 50-policy boundary condition (boundary), predictable performance
  (determinism), time calculations (overflow_safety).
- **Previous count:** 2 classes
- **New count:** 5 classes

---

## Decision 3: SYS-REQ obligation_checklist addition (KEY GAP)

**Context:** SYS-REQ files previously only had `obligation_class` (singular). They now
also carry `obligation_checklist` (plural) enumerating ALL obligation classes that the
requirement's code path satisfies.

**Pattern applied:** Each SYS-REQ gets a checklist that includes its primary class plus
additional classes matching the code behavior:

| SYS-REQ | Class | Checklist |
|---------|-------|-----------|
| 008 | nominal | nominal, error_handling, determinism |
| 010 | error_handling | error_handling, determinism, nil_safety |
| 011 | access_denied | access_denied, error_handling, determinism |
| 012 | malformed_input | malformed_input, error_handling, determinism |
| 013 | nominal | nominal, policy_merge, determinism |
| 014 | nominal | nominal, determinism, idempotency |
| 015 | nominal | nominal, rate_limit_boundary, determinism, overflow_safety |
| 016 | policy_merge | policy_merge, determinism, idempotency |
| 017 | policy_merge | policy_merge, determinism |
| 018 | nominal | nominal, determinism, idempotency |
| 019 | nominal | nominal, error_handling, determinism, idempotency |
| 020 | error_handling | error_handling, nil_safety, determinism, malformed_input |
| 021 | nominal | nominal, rate_limit_boundary, determinism, overflow_safety, monotonicity, nil_safety, commutativity |
| 022 | rate_limit_boundary | rate_limit_boundary, determinism, nil_safety |
| 023 | nominal | nominal, rate_limit_boundary, determinism, overflow_safety, commutativity, nil_safety |
| 024 | access_denied | access_denied, error_handling, atomicity |
| 025 | access_denied | access_denied, error_handling, atomicity |
| 026 | access_denied | access_denied, error_handling, atomicity |
| 027 | nominal | nominal, determinism, panic_free_input_handling |
| 028 | access_denied | access_denied, determinism, atomicity, panic_free_input_handling |
| 029 | nominal | nominal, error_handling, determinism |
| 030 | nominal | nominal, policy_merge, determinism |
| 031 | nominal | nominal, determinism, idempotency |
| 032 | nominal | nominal, determinism, boundary |
| 033 | nominal | nominal, error_handling |
| 040 | error_handling | error_handling, determinism |
| 041 | rate_limit_boundary | rate_limit_boundary, determinism, boundary |
| 042 | error_handling | error_handling, nil_safety, panic_free_input_handling |
| 043 | policy_merge | policy_merge, determinism |
| 044 | nominal | nominal, boundary, overflow_safety, determinism |

**What was NOT added:**
- SYS-REQ-009 is retired (numbering gap placeholder) — no changes made
- `concurrent` was not added to individual SYS-REQ checklists because concurrency is a
  system-level property of the overall Apply call, not of individual merge operations
- `monotonicity` was only added to SYS-REQ-021 (rate limit application) where the
  highest-rate-wins rule exhibits monotonic behavior
- `access_denied` was removed from STK-REQ-002 checklist — ClearSession is an internal
  operation, not an access control boundary
- `malformed_input` was removed from STK-REQ-006 checklist — idle-safety is about state
  machine purity, not input validation

---

## Decision 4: Classes deliberately NOT added

The following were considered but rejected:

- `crypto_agility` — Not relevant; policy engine does not perform cryptographic operations
- `disk_quota` — No filesystem writes in the policy engine
- `path_traversal_prevented` — No filesystem path operations
- `auth_required` — Policy engine is an internal component, not an auth endpoint
- `rate_limit_respected` — The policy engine IS the rate limit enforcer; applying this to
  itself would be circular

---

## Decision 5: concurrent class scoping

`concurrent` was only added to STK-REQ-001 (the top-level Apply orchestrator) because
concurrent access is primarily a concern at the Apply entry point, not in individual merge
sub-operations. The race detector evidence requirement ensures the overall system is tested
for concurrent safety.

Not added to individual SYS-REQs because:
- Each SYS-REQ describes a single logical operation (e.g., "merge access rights")
- Concurrency safety is a property of the data structures, not individual operations
- Adding `concurrent` to every SYS-REQ would create noise without actionable information

---

## Verification Results

- **catalog suggest:** Shows all new classes recognized; only low-confidence generic
  framework suggestions remain (SHA, OWASP, etc.) — no domain-specific gaps
- **audit (baseline scope):** 0 errors, 0 warnings — no regressions
- **audit (--scope full):** Reports `obligation_completeness` gaps — some pre-existing
  (classes like `commutativity`, `boundary`, `determinism` were in STK-REQ checklists but
  never mapped as primary `obligation_class` of any SYS-REQ), some from new additions.
  Full resolution would require either new SYS-REQs or obligation suppressions.
- **Total obligation classes in proof.yaml:** 17 (was 13)

## Known Remaining Gaps (--scope full audit)

The following classes in STK-REQ obligation_checklists are not covered by any SYS-REQ
with a matching `obligation_class`:

| STK-REQ | Uncovered classes |
|---------|------------------|
| STK-REQ-001 | overflow_safety, concurrent, atomicity |
| STK-REQ-002 | determinism, idempotency, malformed_input |
| STK-REQ-003 | overflow_safety, nil_safety |
| STK-REQ-004 | overflow_safety, error_handling, nil_safety |
| STK-REQ-005 | atomicity, determinism, nil_safety, panic_free_input_handling |
| STK-REQ-006 | determinism, panic_free_input_handling |
| STK-REQ-007 | boundary, determinism, overflow_safety |

Note: These gaps exist because `obligation_completeness` checks against the primary
`obligation_class` field (not the `obligation_checklist`). Many of these are new SYS-REQ
classes that describe concerns shared across multiple existing requirements rather than
being the primary focus of any single one. Resolving fully would require creating new
cross-cutting SYS-REQs or adding obligation suppressions to the STK-REQs.

## Files Modified

- `proof.yaml` — Added 4 new obligation classes (overflow_safety, concurrent, atomicity,
  panic_free_input_handling)
- `specs/stakeholder/requirements/STK-REQ-001.req.yaml` — Added overflow_safety, concurrent, atomicity
- `specs/stakeholder/requirements/STK-REQ-002.req.yaml` — Added determinism, idempotency, malformed_input
- `specs/stakeholder/requirements/STK-REQ-003.req.yaml` — Added overflow_safety, nil_safety
- `specs/stakeholder/requirements/STK-REQ-004.req.yaml` — Added overflow_safety, error_handling, nil_safety
- `specs/stakeholder/requirements/STK-REQ-005.req.yaml` — Added atomicity, determinism, nil_safety, panic_free_input_handling
- `specs/stakeholder/requirements/STK-REQ-006.req.yaml` — Added determinism, panic_free_input_handling
- `specs/stakeholder/requirements/STK-REQ-007.req.yaml` — Added boundary, determinism, overflow_safety
- 22 SYS-REQ files — Added obligation_checklist to each
- `docs/internal/phase-obligation-enrichment-decision-log.md` — This file
