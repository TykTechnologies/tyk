# Phase: Scoped ReqProof Stabilization -- Current Warning Disposition

Date: 2026-06-19

## Goal

Bring the currently scoped Tyk ReqProof slice into a truthful strict-audit posture
without claiming full-repo completion. The audit policy remains strict:

- `project.audit.fail_level: warn`
- `project.workflow.fail_level: warn`
- `verification_scope_complete` remains enabled and visible
- no waivers
- no warning suppression
- no obligation suppressions
- no fake `// MCDC` witnesses
- no no-op trigger-false witnesses

This phase is not the full package-onboarding wave. Most production Go files are
still intentionally visible as out of scope until they have real product
requirements, traces, and evidence.

## Current Audit Snapshot

Command:

```sh
proof audit --format markdown --max-findings 20
```

Result:

```text
Errors: 0
Warnings: 5
```

The remaining warnings are intentionally not hidden. Each is classified below by
the honest disposition required to close it.

## Warning Disposition

| Check | Current finding | Disposition | Why it remains |
| --- | --- | --- | --- |
| `verification_scope_complete` | 24/447 declared production source files covered | full-scope onboarding required | The current requirement hierarchy covers the scoped policy/helper slice only. Broad packages such as `apidef`, `gateway`, `storage`, `rpc`, certificates, plugins, and coprocess need product-level STK/SYS hierarchy and package onboarding waves before the scope warning can honestly clear. |
| `spec_lint_status_vs_review` | `SW-REQ-007` and `SW-REQ-008` are `status=review` while `verification.review.status=in_review` by `agent:codex` | human review required | Advancing these to approved requires a real human review signature. Downgrading them to draft would be an authored lifecycle change, not a proof fix. The warning should stay visible until a human reviews or chooses a lifecycle action. |
| `authored_delta_expected` | `internal/policy/apply.go` lacks current no-authored-change review for 43 linked requirements | real impact review required | The branch diff against `origin/master` contains executable behavior changes in `apply.go` (nil-store/session guards, quota sentinel handling, deterministic root update behavior, and related policy behavior). It is not a comment-only proof annotation change, so a blanket agent no-authored-change review would be dishonest. |
| `suspect_clean` | 35 suspect links | human trace review required | `proof trace review --suspect` records a human signature and correctly rejects `agent:codex`. These links should remain visible until a human reviews the stale trace ownership. |
| `mcdc_coverage` | 43/364 uncovered rows across 27 partial requirements | ReqProof tooling gap and model refinement required | Most remaining rows are trigger-false/no-action rows from implication-shaped requirements such as `!operation_requested | result_returned`, paired with invariant-violation rows. Direct helper tests cannot honestly prove the no-action row because calling the helper is the request. |

## MC/DC Evidence Policy For This Phase

Rows are handled using the following rule:

- A real executable path gets a real `// MCDC` row only when the test body
  actually drives and asserts that behavior.
- Trigger-false/no-action rows remain red unless there is concrete no-action
  evidence or ReqProof gains an explicit row-level no-action evidence mechanism.
- `//mcdc:ignore` is allowed only for true invariant or guarantee violation
  rows after the positive rows are already witnessed.
- Any ignore must include a clear category and reason.
- A real product defect becomes a KnownIssue, not an assumption or waiver.

The trigger-false/no-action witness gap is tracked upstream:

- `probelabs/reqproof#257` -- Require explicit no-action evidence on
  trigger-false MC/DC row witnesses.

## Current Known Issues To Keep Visible

The current audit reports nine active KnownIssues. They are intentionally
visible product or platform debts, not assumptions:

- `KI-MODEL-DELETE-LEGACY-LOOKUP`
- `KI-OSUTIL-SYMLINK-ESCAPE`
- `KI-POLICY-APPLY-NONATOMIC-MALFORMED-PARTITION`
- `KI-POLICY-APPLY-NONATOMIC-ORG-MISMATCH`
- `KI-POLICY-APPLY-PARTIAL-MULTIPOLICY-ERROR`
- `KI-POLICY-SHARED-SESSION-RACE`
- `KI-RATE-QUOTA-HEADER-INT-NARROWING`
- `KI-SANITIZE-MALFORMED-PERCENT`
- `KI-SANITIZE-WINDOWS-VOLUME-PATH`

Future changes that discover real bad behavior should add or update KnownIssues
with reproducing evidence instead of using assumptions, accepted risks, or
requirement ignores.

## Next Honest Closure Paths

1. Human review path:
   - Review `SW-REQ-007` and `SW-REQ-008` lifecycle/review state.
   - Run `proof trace review --suspect` as a human reviewer if the stale links
     are still correct.

2. `internal/policy/apply.go` impact path:
   - Review the executable behavior changes against the 43 owning requirements.
   - Update requirements, design docs, tests, or KnownIssues where behavior
     changed.
   - Record impact reviews only for requirements whose authored intent and
     documented design truly remain correct.

3. MC/DC model/tooling path:
   - Do not add no-op tests for trigger-false rows.
   - Refine requirements or variable roles where activation/no-action rows are
     not meaningful executable obligations.
   - Use the upstream ReqProof no-action evidence mechanism when available.

4. Scope onboarding path:
   - Add product capability hierarchy by domain, not by package name.
   - Bring production packages into `verification_scope.include` in batches only
     after real STK/SYS/SW requirements, traces, and tests exist.
