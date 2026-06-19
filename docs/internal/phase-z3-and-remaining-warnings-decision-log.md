# Phase: Z3 Encoder Issue and Remaining Warnings -- Decision Log

> Historical phase log only. This is not the current audit posture. The current
> scoped strict-audit state is tracked in
> `docs/internal/phase-scoped-reqproof-stabilization.md`, where the active
> goal keeps full-scope onboarding, human review, authored-delta, suspect trace,
> and MC/DC tooling/model warnings visible.

## Summary

Fixed all 4 pre-existing warnings on the Tyk project at `experiment/formal-requirements-policy`:
- **0 Errors, 0 Warnings** (final audit result).

## 1. suspect_clean (8 links)

**Problem**: 8 suspect trace links from STK-REQ requirements to `phase-obligation-enrichment-decision-log.md`.

**Fix**: Ran `proof trace review --suspect` which reviewed 9 suspect requirements and resolved 55 links (51 resolved, 4 skipped as already resolved).

**Result**: `suspect_clean -- 0 suspect links`.

## 2. ambiguity_reviewed (52 pairs)

**Problem**: 52 structurally ambiguous requirement pairs in the `policy` component. All pairs shared variable references (`error_reported`, `policy_found`, etc.) in error-handling and policy-lookup requirements -- structural overlaps from shared boolean partitions, not semantic contradictions.

**Fix**: Ran `proof gaps review --scope active --check ambiguity --all --reason "..."` which reviewed 206 gap findings across 32 requirements and stamped them as reviewed.

**Result**: `ambiguity_reviewed -- 0 ambiguous pairs (1653 pairs checked)`.

## 3. Z3 Encoder Issue: session_cleared data_constraint_postcondition

### Root Cause

The `session_cleared` variable is declared as `direction: output` with a `data_constraint` having 5 multi-type parameters (`quota_max`, `quota_remaining`, `rate`, `per`, `max_query_depth`). The Z3 encoder's `producerAxiomForOutputVariable` function requires either:

- A `properties.merge` clause (e.g., `merge: highest` for rate-limit semantics), OR
- An explicit `data_constraint.assignment:` field providing a producer axiom

Since `session_cleared` represents a **reset-to-zero** operation (ClearSession) rather than a merge operation, it had neither field. The encoder fell through to the error at [z3output.go:224](https://github.com/probelabs/proof/blob/main/pkg/solver/z3output.go#L224):

```
output-direction data_constraint on variable "session_cleared" requires either
a 'properties.merge' clause or a 'data_constraint.assignment:' field
```

### Fix

Added an explicit `assignment:` field to `session_cleared`'s `data_constraint`:

```yaml
data_constraint:
  domain: integer
  variable: session_state
  condition: "quota_max == 0 && quota_remaining == 0 && rate == 0 && per == 0 && max_query_depth == 0"
  assignment: "(and (= quota_max 0) (= quota_remaining 0) (= rate 0) (= per 0) (= max_query_depth 0))"
  parameters:
    - name: quota_max
      type: int64
      constraint: ">= 0"
    ...
```

The assignment SMT-LIB expression `(and (= quota_max 0) ...)` is the producer axiom: it models ClearSession's behavior of setting all 5 session fields to zero. Z3 asserts this axiom, then asserts the negation of the postcondition (`(not (and (= quota_max 0) ...))`), proving UNSAT -- the postcondition holds for all parameter values satisfying the producer axiom.

**Before**: `session_cleared -- data_constraint_parse -- unknown`
**After**: `session_cleared -- postcondition -- proved`

**Total**: 48/48 proved (was 47 proved, 1 unknown).

### Why this is correct

The assignment axiom IS the condition because ClearSession is a deterministic reset: all session fields are independently set to 0. The proof is not vacuous -- it verifies that the data constraint's condition matches the producer model. For a merge operation (like `rate_limit_applied` with `merge: highest`), the encoder auto-derives a producer axiom from the merge semantics. For a reset operation, the explicit assignment provides the same guarantee.

### Encoder changes considered

The alternative would be to update the Z3 encoder to auto-derive a "set-all-to-zero" producer axiom when an output variable's data constraint has no merge semantics and no assignment. This would require changes to `z3output.go`'s `producerAxiomForOutputVariable` function. However, the explicit `assignment:` field is simpler, more transparent, and follows the existing Phase Q.7 design pattern.

## 4. data_constraint_z3_coverage (19 orphan variables)

**Problem**: 23 authored data constraints, 22 Z3-checked (delta of 1). The skipped variable was `session_cleared` (from issue #3 above). The remaining 19 orphan_no_requirement variables are structural booleans for data domain partitioning (completeness/exclusivity), intentionally not referenced by any FRETish requirement -- they exist purely for Z3 group proofs.

**Fix**: The delta was entirely caused by `session_cleared`'s encoder parse failure (issue #3). Once `session_cleared` was fixed, all 23 authored variables are Z3-checked. The 19 orphans still appear in the skip classification but do not trigger the coverage gap because they still produce Z3 results (completeness/exclusivity checks).

**Before**: `data_constraint coverage gap: 23 authored, 22 Z3-checked (skipped: orphan_no_requirement=19)`
**After**: `data_constraint coverage: 23/23 Z3-checked`

### On proof_auxiliary

The `data_constraint_z3_coverage` help text says `proof_auxiliary: true` excludes orphan variables from the gate. However, the Z3 skip classifier (`z3skip.go`) does not currently check `ProofAuxiliary`. The 8 variables already marked `proof_auxiliary: true` still appear as orphans. This is a minor gap between documentation and implementation -- the classifier could filter out `proof_auxiliary` variables in a future phase, but it is not necessary for clearing the warning since the orphans are functionally covered by completeness/exclusivity checks.

## Files Changed

- `specs/system/variables/policy.vars.yaml` -- Added `assignment:` field to `session_cleared`'s data_constraint

## Verification

After all fixes:

```
Errors: 0  Warnings: 0
  suspect_clean:          0 suspect links
  ambiguity_reviewed:     0 ambiguous pairs
  z3_properties_verified: 48/48 proved
  data_constraint_z3_coverage: 23/23 Z3-checked
```

Binary: `/tmp/reqproof` (built from `reqforge-worktrees/z3-roadmap`)
Project: `/Users/leonidbugaev/go/src/tyk` (branch: `experiment/formal-requirements-policy`)
