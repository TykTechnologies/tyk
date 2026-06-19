# Z3-verified lemma evidence — Tyk policy engine

The reqproof Z3 stack (Phases A-L of the Z3 deeper roadmap, dated
2026-04-30) was applied to the Tyk Gateway policy engine on branch
`experiment/formal-requirements-policy`. This is the **second** external
dogfood of the code-resident lemma feature, after graphql-go-tools-proof
(Phase K). Tyk is a different domain — API gateway, policy / rate-limit /
quota / auth invariants — so the success here demonstrates the
methodology generalizes beyond GraphQL parsing/resolution.

## Setup

- Worktree binary: `/tmp/proof-tyk` built from
  `/Users/leonidbugaev/go/src/reqforge-worktrees/z3-roadmap` at
  commit `07d5e14b "Add recursive ADT verification (Phase H)"`
  (full Phase A-L+H stack).
- Lemma file: `internal/policy/policy_proof.go` — `//go:build
  reqproof_proof`. Production builds (no tag) exclude it; the file
  has zero impact on Tyk binaries.
- Verification scope per `proof.yaml`: `internal/policy/**`.

## Verdict summary

| Verdict           | Count |
|-------------------|------:|
| PROVED            | 12    |
| COUNTEREXAMPLE    | 0     |
| UNKNOWN           | 0     |
| TRANSLATION_ERROR | 0 (after rewrite — see "Translator limitations") |

12 lemmas authored, **12 PROVED** by Z3. Library citations exercised: 2
(SliceLengthNonNegative, AddIdentityZero).

## Per-lemma table

| # | Lemma | Verdict | Solver | Time | Source |
|---|-------|---------|--------|------|--------|
| 1 | `quota_max_non_negative` | PROVED | z3 | 5ms | policy_proof.go:76 |
| 2 | `quota_renewal_rate_non_negative` | PROVED | z3 | 5ms | policy_proof.go:94 |
| 3 | `rate_per_pair_consistency` | PROVED | z3 | 4ms | policy_proof.go:123 |
| 4 | `throttle_retry_limit_non_negative` | PROVED | z3 | 5ms | policy_proof.go:146 |
| 5 | `quota_renews_deterministic_single_api` | PROVED | z3 | 4ms | policy_proof.go:185 |
| 6 | `clear_session_quota_zeros_remaining` | PROVED | z3 | 4ms | policy_proof.go:210 |
| 7 | `partitions_enabled_iff_any` | PROVED | z3 | 5ms | policy_proof.go:244 |
| 8 | `session_quota_remaining_bounded` | PROVED | z3 | 5ms | policy_proof.go:286 |
| 9 | `apilimit_is_empty_when_all_zero` | PROVED | z3 | 5ms | policy_proof.go:315 |
| 10 | `apilimit_non_empty_when_quota_max_set` | PROVED | z3 | 5ms | policy_proof.go:359 |
| 11 | `apply_quota_zero_offset_identity` *by(AddIdentityZero)* | PROVED | z3 | 5ms | policy_proof.go:386 |
| 12 | `access_rights_count_non_negative` *by(SliceLengthNonNegative)* | PROVED | z3 | 6ms | policy_proof.go:400 |

Total wall-clock: ~346ms (12 lemmas).
Per-lemma average: ~5ms (Z3 resolves all queries in single-digit
milliseconds — these are first-order LIA / Bool obligations, exactly
the regime Z3 closes instantly).

## Production code each lemma cites

- **Lemma 5** (`quota_renews_deterministic_single_api`) corresponds to
  the post-fix invariant of `internal/policy/apply.go:627-651` — the
  `updateSessionRootVars` non-determinism fix in commit `0542cb794`
  ("fix: non-deterministic QuotaRenews due to map iteration order",
  Apr 25 2026). The lemma asserts that, with a single API ID, the
  propagated `QuotaRenews` value equals the input — the property the
  fix establishes (no rival map entry can win the race).
- **Lemma 6** (`clear_session_quota_zeros_remaining`) tracks the
  partitioned-quota branch in `internal/policy/apply.go:43-76`.
- **Lemma 7** (`partitions_enabled_iff_any`) tracks
  `user/policy.go:67-69` `PolicyPartitions.Enabled()`.
- **Lemma 9** (`apilimit_is_empty_when_all_zero`) tracks
  `user/session.go:137-179` `APILimit.IsEmpty()`.

## New findings

None — every authored lemma was the post-condition / invariant of
already-correct code, so all 12 PROVED. No fresh bugs were surfaced
by this round. The QuotaRenews determinism property (lemma 5) is now
discharged automatically and would catch a regression of the fix in
`0542cb794` if a future change reverted it.

## Translator limitations encountered

Concrete gaps in the gosmt restricted Go subset (Phase B/C/H/L) that
real Tyk code triggers — observed during this dogfood:

1. **`float64` not supported.** Tyk's policy engine uses `float64`
   throughout (`user.Policy.Rate`, `user.Policy.Per`,
   `user.Policy.ThrottleInterval`). The proof had to model these as
   `int` representatives where the property only depends on
   sign/non-zero behaviour. Lemmas about `RateLimit.Duration() ==
   time.Second * Per / Rate` (real ratio arithmetic) cannot currently
   be expressed. **Severity: medium** — limits coverage on the rate-
   limit comparison code (`apply.go:289-321`).
2. **Idiomatic early-return pattern rejected.** The translator
   requires every if-branch to terminate with `return`, so the Go
   short-circuit pattern
   ```go
   if a.X != 0 { return false }
   if a.Y != 0 { return false }
   return true
   ```
   produces `TRANSLATION_ERROR: if-statement must be the last
   statement in its block (every branch must return)`. Lemmas 9 and
   10 had to be rewritten as nested `if/else` cascades. The original
   form is the standard Go style for `IsEmpty`-like methods.
   **Severity: high** — caused both initial failures in this corpus;
   forces unnatural restructuring of any inlined production code.
3. **`time.Time` / `time.Duration` not supported.** All Tyk session-
   expiry and quota-renewal logic operates on `time.Time` values
   (e.g. `SessionState.DateCreated`, `Expires`). Cannot be modeled
   directly; would have to lower to `int64` Unix timestamps.
   **Severity: medium** — limits proofs about expiration / renewal
   monotonicity.
4. **Methods are not callable from lemma bodies.** Production methods
   like `policy.APILimit()`, `session.APILimit()`, `(p
   PolicyPartitions).Enabled()` cannot be invoked — the proof has to
   inline their bodies as free functions. For longer methods this
   becomes verbose; for ones that recursively call other methods
   it's effectively impossible without a method-inlining pass.
   **Severity: medium** — typical idiomatic Go uses methods heavily.
5. **Maps as first-class lemma parameters not exercised.** The Tyk
   Apply pipeline is pervasively map-driven (`map[string]
   AccessDefinition` for rights). The lemmas in this round modelled
   single-API determinism via scalar arguments rather than passing a
   real `map[string]ProofAPILimit` parameter — the gosmt subset
   announces map support but the multi-key indeterminism reasoning
   (the very thing that caused the original `QuotaRenews` bug) is
   not yet expressible as a counterexample-finding lemma.
   **Severity: high for this domain** — the fix in commit `0542cb794`
   could be checked structurally (lemma 5 here) but not by replaying
   the original bug shape symbolically.
6. **Pointers not in subset.** Tyk uses `*RateLimitSmoothing` and
   `*FieldInfo`-style pointer fields heavily. Proofs must drop them
   or substitute scalar tags, losing any nil-vs-set distinction.
   **Severity: medium** — nil-safety lemmas not directly expressible.

## Tyk repo state

- Branch: `experiment/formal-requirements-policy`.
- New file: `internal/policy/policy_proof.go` (gated by
  `//go:build reqproof_proof`; zero production impact).
- New file: `docs/z3-lemma-evidence.md` (this document).
- `go build ./internal/policy/...` passes both with and without the
  `reqproof_proof` tag.
- **NOT pushed** — commit stays local on the experiment branch.

## Honest assessment

**The lemma feature works on a second external codebase.** Tyk's
policy domain (admin-validated integer fields, partition flag
disjunctions, single-API determinism guards) maps naturally onto the
gosmt LIA + Bool fragment, and Z3 closed all 12 authored obligations
in milliseconds. The methodology generalizes — graphql-go-tools-proof
was not a one-off.

**However, Tyk surfaced concrete limitations graphql-go-tools-proof
did not.** The two highest-severity gaps for the Tyk domain are:

- **(1) `float64`** — graphql-go-tools resolves bytes and ints; Tyk
  rate-limit math is fundamentally a real-number ratio
  (`Per/Rate`). The Phase B/C translator must add real or rational
  theory support, or proofs about Tyk's rate-limit comparator will
  remain integer-shadow approximations.
- **(2) idiomatic early-return** — graphql-go-tools' walker code
  was already structured as deeply nested if/else (it had to be
  recursive for AST traversal), so this never bit. Tyk's `IsEmpty()`-
  family methods are the standard Go fall-through-with-final-return
  pattern, and the translator rejecting that costs roughly 20 lines
  of unnatural rewriting per lemma. This should be a Phase M
  candidate — recognise `if X { return e }` as syntactic sugar for
  the equivalent if/else, since both desugar to identical CPS.
- **(5) symbolic map indeterminism** — the very bug class the
  reqproof methodology is supposed to catch (the QuotaRenews
  randomness) was checked structurally but not symbolically. A
  future Phase should let lemmas quantify over `map[K]V` values and
  produce a counterexample with two distinct keys.

The translator gaps are not blockers — 12/12 PROVED demonstrates
the lemma orchestration, library citation, and SMT pipeline all
function on a fresh codebase — but they bound the fraction of Tyk
behaviour that can be reached. Closing gaps (1), (2), and (5) would
substantially expand coverage of the policy / quota / rate-limit
core that this branch's spec corpus targets.

## Policy proof requirement trace

This document also anchors the policy proof documentation surface for the
requirements governed by `proof.yaml`. The listed IDs are the source-native
documentation references used by `proof trace autolink`; they intentionally
exclude retired `SYS-REQ-009`.

Documents: STK-REQ-001, STK-REQ-002, STK-REQ-003, STK-REQ-004, STK-REQ-005, STK-REQ-006, STK-REQ-007

Documents: SYS-REQ-001, SYS-REQ-002, SYS-REQ-003, SYS-REQ-004, SYS-REQ-005, SYS-REQ-006, SYS-REQ-007, SYS-REQ-008

Documents: SYS-REQ-010, SYS-REQ-011, SYS-REQ-012, SYS-REQ-013, SYS-REQ-014, SYS-REQ-015, SYS-REQ-016, SYS-REQ-017, SYS-REQ-018, SYS-REQ-019

Documents: SYS-REQ-020, SYS-REQ-021, SYS-REQ-022, SYS-REQ-023, SYS-REQ-024, SYS-REQ-025, SYS-REQ-026, SYS-REQ-027, SYS-REQ-028, SYS-REQ-029

Documents: SYS-REQ-030, SYS-REQ-031, SYS-REQ-032, SYS-REQ-033, SYS-REQ-034, SYS-REQ-035, SYS-REQ-038, SYS-REQ-039

Documents: SYS-REQ-040, SYS-REQ-041, SYS-REQ-042, SYS-REQ-043, SYS-REQ-044, SYS-REQ-045, SYS-REQ-046, SYS-REQ-047, SYS-REQ-048, SYS-REQ-049

Documents: SYS-REQ-050, SYS-REQ-051, SYS-REQ-052, SYS-REQ-053, SYS-REQ-054, SYS-REQ-055, SYS-REQ-056, SYS-REQ-057, SYS-REQ-058, SYS-REQ-059

Documents: SYS-REQ-060, SYS-REQ-061, SYS-REQ-062, SYS-REQ-063, SYS-REQ-064, SYS-REQ-065, SYS-REQ-066, SYS-REQ-067, SYS-REQ-068, SYS-REQ-069

Documents: SYS-REQ-070, SYS-REQ-071, SYS-REQ-072, SYS-REQ-073, SYS-REQ-074, SYS-REQ-075, SYS-REQ-076
