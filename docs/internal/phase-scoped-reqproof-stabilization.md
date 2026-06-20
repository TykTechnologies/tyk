# Phase: Scoped ReqProof Stabilization -- Current Warning Disposition

Date: 2026-06-20

## Goal

Track the current truthful baseline on the path to full Tyk ReqProof onboarding
with zero audit warnings. The current state is not accepted as complete; it is
the honest backlog after removing known false evidence. The audit policy remains
strict:

- `project.audit.fail_level: warn`
- `project.workflow.fail_level: warn`
- `verification_scope_complete` remains enabled and visible
- no waivers
- no warning suppression
- no obligation suppressions
- no fake `// MCDC` witnesses
- no no-op trigger-false witnesses

Most production Go files are still visible as out of scope until they have real
product requirements, traces, and evidence. The path to zero warnings is full
onboarding, not narrowing the audit or hiding the warning.

## Current Audit Snapshot

Command:

```sh
proof audit --format markdown --max-findings 20
```

Result:

```text
Errors: 0
Warnings: 2
```

The remaining warnings are intentionally not hidden. Each is classified below by
the honest disposition required to close it.

## Warning Disposition

| Check | Current finding | Disposition | Why it remains |
| --- | --- | --- | --- |
| `verification_scope_complete` | 116/447 declared production source files covered | full-scope onboarding required | The current requirement hierarchy covers the scoped policy/helper slice only. Broad packages such as `apidef`, `gateway`, `storage`, `rpc`, certificates, plugins, and coprocess need product-level STK/SYS hierarchy and package onboarding waves before the scope warning can honestly clear. |
| `mcdc_coverage` | 52/385 uncovered rows across 29 partial requirements | ReqProof tooling gap and model refinement required | Remaining rows are trigger-false/no-action rows from implication-shaped requirements such as `!operation_requested | result_returned`, plus paired invariant-violation rows whose positive row set is still incomplete while the trigger-false row is unresolved. Direct helper tests cannot honestly prove the no-action row because calling the helper is the request. |

Closed during this pass:

- `authored_delta_expected` was closed by real impact reviews for
  `internal/policy/apply.go` and related `internal/policy/util.go` ownership.
- `spec_lint_status_vs_review` was closed for `SW-REQ-007` and `SW-REQ-008`
  after explicit chat delegation from `human:buger`; the approval comments
  state that MC/DC gaps remain tracked separately.
- `suspect_clean` was closed after explicit chat delegation from `human:buger`
  to review the current suspect trace set; the trace review does not waive
  MC/DC coverage or product KnownIssues.

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

## Current MC/DC Backlog Classification

The current 52 uncovered MC/DC rows are intentionally left visible. They fall
into two closure groups:

1. Trigger-false/no-action rows: leave red until there is real no-action
   evidence, requirement refinement, or the ReqProof mechanism from
   `probelabs/reqproof#257`.
2. Paired invariant-violation rows: leave red while the paired trigger-false
   row is unresolved, because the requirement's positive row set is incomplete.

Some trigger-true violation rows may later get real executable witnesses, and
some trigger-false rows may become caller-level no-action tests. This table does
not mark them green in advance. It records the current honest state: no backlog
row has enough evidence to close today, and no backlog row currently requires a
new product KnownIssue.

| Requirement | Missing row shape | Classification | Current disposition |
| --- | --- | --- | --- |
| `SW-REQ-001` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-003` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-004` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-005` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-006` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-081` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-082` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-083` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-084` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-085` | `requested=F,preserved=F => TRUE`; `requested=T,preserved=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-088` | `requested=F,preserved=F => TRUE`; `requested=T,preserved=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-089` | `requested=F,enforced=F => TRUE`; `requested=T,enforced=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-095` | `requested=F,reported=F => TRUE`; `requested=T,reported=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-098` | `requested=F,scoped=F => TRUE`; `requested=T,scoped=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-100` | `requested=F,returned=F => TRUE`; `requested=T,returned=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-103` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-108` | `requested=F,determined=F => TRUE`; `requested=T,determined=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-109` | `requested=F,determined=F => TRUE`; `requested=T,determined=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-110` | `requested=F,determined=F => TRUE`; `requested=T,determined=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-007` | `identity_requested=F,identifier_available=T,identifier_valid=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SW-REQ-008` | `store_requested=F,lookup_returned=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-080` | `api_list_requested=F,api_list_result_returned=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-091` | `validation_requested=F,path_within_target=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-093` | `validation_requested=F,component_accepted=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-102` | `operation_requested=F,operation_confined=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
The earlier invariant-only candidates `SYS-REQ-096`, `SYS-REQ-097`,
`SYS-REQ-099`, and `SYS-REQ-101` were closed with narrow defensive
`//mcdc:ignore` rows after `proof mcdc show` confirmed their positive rows were
already witnessed. No refused, stale, or dangling MC/DC exemptions remain.
`SYS-REQ-092` was closed with real executable evidence: safe archive paths are
presented and accepted, proving `unsafe_archive_path_presented=F` and
`unsafe_archive_path_rejected=F`.

Sub-agent cross-check on 2026-06-19 reached the same row-level classification
for the original backlog and found no remaining missing row that looked like a
new product KnownIssue. Existing KnownIssue-covered rows were already witnessed
rather than part of this backlog.

## Current Known Issues To Keep Visible

The current audit reports eight active KnownIssues. They are intentionally
visible product or platform debts, not assumptions:

- `KI-MODEL-DELETE-LEGACY-LOOKUP`
- `KI-OSUTIL-SYMLINK-ESCAPE`
- `KI-POLICY-APPLY-NONATOMIC-MALFORMED-PARTITION`
- `KI-POLICY-APPLY-NONATOMIC-ORG-MISMATCH`
- `KI-POLICY-APPLY-PARTIAL-MULTIPOLICY-ERROR`
- `KI-POLICY-SHARED-SESSION-RACE`
- `KI-SANITIZE-MALFORMED-PERCENT`
- `KI-SANITIZE-WINDOWS-VOLUME-PATH`

This phase does not fix or close KnownIssues. Existing fixed-status
KnownIssues, if present in `.proof/known-issues`, are historical records from
earlier repair work. The active scoped stabilization posture is only that
currently open product debts stay visible and are not converted into
assumptions, waivers, or MC/DC ignores.

KnownIssue evidence freshness refresh is also outside this phase. As of this
snapshot, `proof known-issue check` reports stale freshness metadata for
historical evidence manifests after nearby proof/test files changed. That is a
separate evidence-refresh/review activity, not a reason to mark product issues
fixed or to hide them from the current strict audit.

Future changes that discover real bad behavior should add or update KnownIssues
with reproducing evidence instead of using assumptions, accepted risks, or
requirement ignores.

## Next Honest Closure Paths

1. MC/DC model/tooling path:
   - Do not add no-op tests for trigger-false rows.
   - Refine requirements or variable roles where activation/no-action rows are
     not meaningful executable obligations.
   - Use the upstream ReqProof no-action evidence mechanism when available.

2. Scope onboarding path:
   - Add product capability hierarchy by domain, not by package name.
   - Bring production packages into `verification_scope.include` in batches only
     after real STK/SYS/SW requirements, traces, and tests exist.
   - Recent increments include `pkg/validator` custom-policy-ID validation,
     `dnscache` local DNS cache storage and manager behavior,
     `internal/service/core` upstream-auth request-context helpers, and
     `apidef/mcp` embedded MCP schema validation with the local
     `internal/service/gojsonschema` and `internal/errors` facades,
     `internal/errors` diagnostic classification, `internal/oasutil` OAS
     path/server helpers, the `user` MCP access-right data model,
     `pkg/schema` OAS visitor/unicode-escape helpers, the
     `internal/middleware` custom middleware enablement helper, the
     `internal/httputil/accesslog` access-log field filter and record helper, the
     `apidef/oas` extension header helper, and the `apidef/oas` MCPPrimitive
     helper shape, the `apidef/oas` readable-duration alias, the
     `apidef/oas` error-override shape helpers, the `apidef/oas` schema example
     extraction helper, the `apidef/oas` internal endpoint shape helper, the
     `apidef/oas` endpoint tracking shape helper, the `apidef/oas` utility
     helper shapes, the `apidef/oas` deprecated-wrapper conversion helper, the
     `apidef/oas` Tyk streaming extension shape, the `apidef/oas` event-handler
     helper shapes, the `apidef/oas` server-regeneration helper shapes, the
     `apidef/oas` validator helper shapes, the `apidef/oas` root extension
     helper shapes, the `apidef/oas` server model helper shapes, and the
     `apidef/oas` URL rewrite helper shapes, and the `apidef/oas` MCPPrimitive
     build-mode guard helpers, the `internal/reflect` support helpers, the
     `pkg/errpack` typed diagnostic error helpers, the
     `internal/service/newrelic` observability adapter helpers, and the
     `apidef/adapter` import interface, GraphQL utility helpers, and GraphQL
     config adapter helpers. They reduce the
     visible scope gap but do not change the remaining warning disposition.
