# ReqProof ticket: tighten MC/DC witnesses for trigger-false rows

Upstream issue: https://github.com/probelabs/reqproof/issues/257

## Title

Require explicit no-action evidence on trigger-false MC/DC row witnesses.

## Problem

Tyk requirements often model package/helper behavior as an implication:

```text
!<operation>_requested | <result>_returned
```

ReqProof expands this into MC/DC rows such as:

```text
<operation>_requested=F, <result>_returned=F => TRUE
<operation>_requested=T, <result>_returned=F => FALSE
<operation>_requested=T, <result>_returned=T => TRUE
```

For an in-process helper requirement, the `requested=F` row is a no-call or
trigger-false row. A unit test that directly exercises the helper normally
cannot prove that row, because calling the helper is the request. A comment that
claims `requested=F` inside a test that invokes the mapped helper is therefore
not valid evidence.

This is not asking ReqProof to guess what every helper is or to add a new
evidence object family. The deterministic rule should be the opposite:

> `// MCDC <REQ-ID>: ...` remains the row witness surface. For trigger-false
> rows, a plain row witness is not enough; the same evidence block must either
> assert the no-action behavior or carry an explicit row-level qualifier that
> explains how absence of the action is known.

Unknown must not become green.

## Observed behavior in Tyk

After removing known-false no-call witness comments, removing refused
trigger-false ignores, and closing the four invariant-only rows that already
had positive witnesses, Tyk reports:

```sh
proof mcdc spec queue --limit 120
```

```text
39/364 witness rows uncovered across 91 requirement(s)
23 partial-row-coverage items
```

Representative current rows:

```text
SW-REQ-001:
  uuid_operation_requested=F, uuid_operation_result_returned=F => TRUE
  uuid_operation_requested=T, uuid_operation_result_returned=F => FALSE

SW-REQ-005:
  netutil_address_lookup_requested=F, netutil_address_lookup_result_returned=F => TRUE
  netutil_address_lookup_requested=T, netutil_address_lookup_result_returned=F => FALSE

SYS-REQ-095:
  usable_node_address_discovery_requested=F, usable_node_addresses_reported=F => TRUE
  usable_node_address_discovery_requested=T, usable_node_addresses_reported=F => FALSE

SYS-REQ-098:
  root_creation_requested=F, root_directory_scoped=F => TRUE
  root_creation_requested=T, root_directory_scoped=F => FALSE
```

Example requirements and evidence:

- `specs/software/requirements/SW-REQ-005.req.yaml`

  ```text
  the netutil shall always satisfy !netutil_address_lookup_requested | netutil_address_lookup_result_returned
  ```

- `internal/netutil/ip_address_test.go`

  ```go
  // MCDC SW-REQ-005: netutil_address_lookup_requested=T, netutil_address_lookup_result_returned=T => TRUE
  func Test_GetIpAddress(t *testing.T) {
      ...
  }
  ```

- `specs/system/requirements/SYS-REQ-098.req.yaml`

  ```text
  the osutil shall always satisfy !root_creation_requested | root_directory_scoped
  ```

- `internal/osutil/osutil_test.go`

  ```go
  // MCDC SYS-REQ-098: root_creation_requested=T, root_directory_scoped=T => TRUE
  func TestNewRoot(t *testing.T) {
      ...
  }
  ```

These current gaps are good: they show the audit is no longer accepting comments
that do not prove the row. The remaining backlog is still dominated by
trigger-false/no-action rows and paired invariant rows whose positive set is
incomplete until the trigger-false row has an honest disposition.

## False-pass risk examples

These examples document the false-pass pattern that the Tyk audit found and
removed. They are intentionally left as red MC/DC rows in the current scoped
audit unless there is real no-action evidence. A future plain `// MCDC` comment
should not be enough to cover these rows when the test body exercises the helper.

Examples found during the Tyk audit:

1. `internal/model/merged_apis_test.go` / `SYS-REQ-080`

   Requirement shape:

   ```text
   !api_list_requested | api_list_result_returned
   ```

   The test can claim:

   ```go
   // MCDC SYS-REQ-080: api_list_requested=F, api_list_result_returned=F => TRUE
   ```

   while the same test constructs and uses the list helper:

   ```go
   list := model.NewMergedAPIList(...)
   got := list.Filter(...)
   ```

2. `internal/model/policies_test.go` / `SW-REQ-007`

   Requirement shape:

   ```text
   !policy_identity_requested | policy_identifier_valid | !policy_identifier_available
   ```

   The test can claim a trigger-false row:

   ```go
   // MCDC SW-REQ-007: policy_identifier_available=T, policy_identifier_valid=F, policy_identity_requested=F => TRUE
   ```

   while each table case calls:

   ```go
   res := model.EnsurePolicyId(tc.input)
   ```

3. `internal/model/policies_test.go` / `SW-REQ-008`

   Requirement shape:

   ```text
   !policy_store_requested | policy_lookup_returned
   ```

   The test can claim:

   ```go
   // MCDC SW-REQ-008: policy_lookup_returned=F, policy_store_requested=F => TRUE
   ```

   while the test constructs and exercises the store:

   ```go
   pols := model.NewPolicies()
   pols.Reload(...)
   pols.PolicyByIdExtended(...)
   ```

4. `internal/sanitize/path_test.go` / `SYS-REQ-093`

   Requirement shape:

   ```text
   !path_component_validation_requested | path_component_accepted
   ```

   The test can claim:

   ```go
   // MCDC SYS-REQ-093: path_component_validation_requested=F, path_component_accepted=F => TRUE
   ```

   while calling:

   ```go
   err := ValidatePathComponent(component)
   ```

## Why this matters

ReqProof help for `mcdc_coverage` says:

```text
add // MCDC <requirement-id>: ... only when the test really proves those rows
```

and:

```text
comments alone are not evidence
```

Under strict MC/DC policy, accepting a trigger-false row from a helper test
can create a false green audit state. In safety-critical terms, this is a false
traceability claim: the evidence says a row was tested, but the executable path
contradicts the row assignment.

This should not be handled by `proof_auxiliary`. Per `proof help
domain-modeling`, `proof_auxiliary` is for solver-bookkeeping variables such as
partition witnesses or derived flags. These `*_requested` variables are
behavioral trigger/request conditions, not proof-only domain facts.

## Deterministic expected behavior

ReqProof should not depend on a Go-specific AST or call graph for the core
solution. Tyk uses Go, but ReqProof supports multiple implementation languages.
The common mechanism needs to be language-agnostic and should extend the
existing requirement-level MC/DC witness/disposition model instead of adding a
separate scenario-evidence concept.

Minimum expected behavior:

1. FRETish/formalization remains the source of Boolean formula structure. The
   new metadata should not duplicate formula roles such as "antecedent" or
   "trigger" when those can be derived from the formula.

2. ReqProof should classify MC/DC rows where an antecedent/request condition is
   assigned `F` as trigger-false/no-action rows.

3. Trigger-false rows should not be covered by a plain `// MCDC` line alone in
   strict mode. Reuse the existing MCDC witness grammar and add a narrow
   row-level qualifier/trailer for no-action evidence if the test's assertion is
   not self-evident.

   Example sketch:

   ```go
   // Verifies: SW-REQ-005
   // MCDC SW-REQ-005: cache_hit=T, netutil_address_lookup_requested=F => TRUE [no-action: spy lookupCalls == 0] [reviewed: human:<id>]
   func TestCallerUsesCachedAddressWithoutLookup(t *testing.T) {
       ...
       require.Equal(t, 0, lookupCalls)
   }
   ```

   The exact trailer syntax can be improved. The important property is that the
   row assignment stays on the existing `MCDC` line, while the no-action claim is
   explicit and reviewable.

4. `proof mcdc show <REQ>` should explain the distinction and print suggested
   fixes for trigger-false rows:

   ```text
   Row assigns request variable F. This is a trigger-false/no-action row.
   A plain MCDC witness is insufficient because a helper/unit test may exercise
   the action while claiming it was not requested.

   Add one of:
     - a real test assertion proving the caller did not invoke the action;
     - a row-level MCDC trailer such as [no-action: spy lookupCalls == 0];
     - a smaller subtest/case-scoped witness with a spy/mock assertion;
     - requirement refinement/domain modeling if the row is not meaningful;
     - or refactor the requirement so the request is a precondition rather than
       a unit-level MC/DC condition.
   ```

5. `proof mcdc spec queue` should surface trigger-false rows that only have
   plain MCDC comments as a distinct actionable category, for example
   `trigger_false_needs_no_action_evidence`.

   The queue finding must be prescriptive. Its fix text should point to the
   existing mechanisms rather than inventing a workaround:

   - add a real no-action assertion and, if needed, a row trailer such as
     `[no-action: spy lookupCalls == 0]`;
   - reference existing ManualEvidence for external/non-code row evidence;
   - use KnownIssue disposition for real product bugs;
   - use domain modeling, assumptions, or requirement refinement for impossible
     or mis-owned rows;
   - use existing `//mcdc:ignore` taxonomy only for guarantee/invariant
     violation rows.

6. Optional language-specific analyzers may strengthen the evidence. For
   example, a Go plugin could use typed call-graph analysis to reject a
   `requested=F` row when the same test definitely reaches a bound symbol. A
   Python/TypeScript/Rust plugin could do the equivalent for that language. But
   these analyzers are optional validators, not the required core mechanism.

7. Existing `//mcdc:ignore` safeguards must remain intact. This mechanism must
   not allow reachable product defects or dead code paths to be hidden.

## Non-goals

- Do not require ReqProof to determine helper identity by naming convention.
- Do not require complete whole-program call-graph precision.
- Do not make Go AST/SSA analysis a prerequisite for the feature.
- Do not make language-specific static analysis the only way to prove or reject
  a row.
- Do not create a separate first-class `scenario-evidence` object family unless
  a concrete use case cannot be expressed as an MC/DC row witness, a
  ManualEvidence reference, KnownIssue disposition, domain fact, or requirement
  refinement.
- Do not treat uncertainty as coverage.
- Do not use `proof_auxiliary` to remove behavioral request variables from
  the proof surface.

## Possible implementation direction

The strongest language-agnostic approach is to extend the existing MC/DC
witness/disposition model:

- FRETish/formalization defines the Boolean condition.
- MC/DC row generation identifies trigger-false/no-action rows.
- A plain `MCDC` line can witness ordinary rows when the test actually proves
  the assignment.
- A trigger-false/no-action row needs a real assertion in the same evidence
  block or an explicit row-level trailer describing the observation.
- External/non-code row evidence, if needed, should reference existing
  ManualEvidence rather than inventing a new evidence store, for example
  `[manual-evidence: ME-123]`.
- Language-specific static analyzers may validate or reject no-action trailers
  when available, but absence of such an analyzer must not create silent green
  coverage.

Potential accepted evidence forms:

- a caller-level test with a spy/mock/counter assertion proving the action was
  not invoked in that scenario;
- a case-scoped or subtest-scoped witness where the scenario is narrow enough to
  support the `F` assignment;
- an MC/DC row trailer that points at existing ManualEvidence for reviewed
  static/external evidence when runtime assertion is not practical;
- requirement refinement, domain modeling, or assumptions when the generated row
  represents an impossible or mis-owned state;
- KnownIssue disposition when the row is unwitnessable because of a real product
  bug;
- or a requirement pattern that treats the request/trigger as a precondition so
  helper unit MC/DC does not demand the no-action row.

The key invariant is that an ordinary helper unit test may prove
`requested=T,result=T` or a reachable `requested=T,result=F` defect row, but it
must not prove `requested=F` unless the evidence is about absence of the action
in that specific witness scenario.
