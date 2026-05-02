# Reqproof Coverage Gaps — Tyk

This document is the standing prioritisation list for Tyk lemma-authoring
work. It captures the production code-paths that the current corpus
(50 PROVED lemmas — 30 in `internal/policy/`, 20 in `user/`) does *not*
yet certify, and groups each gap by the underlying toolchain blocker.

The lemma-internal branch-coverage tool (`proof verify-lemma --coverage`)
reports **100% coverage** of every branch inside every authored lemma.
That metric measures translator surface, not production reach. The gaps
below are production code-paths for which no lemma has yet been written
because of (a) a translator limitation, or (b) authoring work not yet
done. Phase tags refer to the reqproof roadmap.

## Snapshot

| Metric                         | Value |
| ------------------------------ | ----- |
| Lemmas authored                | 50    |
| Lemmas PROVED (z3)             | 50    |
| Lemma-internal branches        | 74    |
| Lemma-internal branches covered| 74    |
| `by(...)` library citations    | 11    |
| Files containing lemmas        | 5     |

## Blocker categories

### A. Phase S.2c.3 — nested loops

The translator does not yet lower a `for` nested inside another `for` to
SMT. Three production helpers depend on this shape and remain unproven:

| Function                               | File:Line                                            | Notes |
| -------------------------------------- | ---------------------------------------------------- | ----- |
| `MergeAllowedURLs`                     | `internal/policy/util.go:13-50`                      | Outer ranges over `[s1, s2]`; inner ranges over each spec. Map-based dedup. |
| `Service.applyACL` (inline in `Apply`) | `internal/policy/apply.go:218-279`                   | Outer over `rights map`, inner over `RestrictedTypes` / `AllowedTypes` / `FieldAccessRights` (apply.go:450, 477, 504). |
| `Service.applyPartitions`              | `internal/policy/apply.go:401-625`                   | Outer over policies; inner over per-API access rights and per-method limits. |

A future Phase S.2c.3 lowering would emit synthetic counters per inner
loop and a product-domain invariant. Until then no lemma can attach
inside these bodies.

### B. Phase S.2c.4 — early-return projection

The break-helper synthesis works (we have 4 lemmas using it). What does
*not* work yet is `return` from inside a loop where the post-loop
projection of a witness must be exposed to the lemma's `proves`
expression — i.e. find-first-position lemmas like:

| Function                             | File:Line                                    | Pattern |
| ------------------------------------ | -------------------------------------------- | ------- |
| `EndpointMethods.Contains`           | `user/session.go` (existing helper)          | `for _, m := range … { if m == x { return true } } return false` — find-existence. |
| `(t *Service).PoliciesEqualTo`       | `internal/policy/apply.go` (signature compare) | `return false` mid-loop on first inequality. |
| `appendIfMissing`                    | `internal/policy/util.go:54-62`              | Internal `slices.Contains`-based skip; not strictly early-return but uses `continue` with a side effect. |

The break-only counter pattern (Phase S.2c.4 baseline) covers these only
in the "did the loop find anything" weak form. The strong form (the
returned witness's index / value lifted into the post-condition) requires
the projection extension.

### C. Phase S.2c.5 — richer monoids

Three production merge helpers compute over a string-keyed map / struct
monoid, not the integer-add monoid the translator currently understands:

| Function                       | File:Line                            | Monoid                         |
| ------------------------------ | ------------------------------------ | ------------------------------ |
| `Service.ApplyJSONRPCMethodLimits` | `internal/policy/apply.go:747-775` | `(map[string]Limit, ⊔=lower-duration)` |
| `Service.ApplyMCPPrimitiveLimits`  | `internal/policy/apply.go:780-810` | `(map[key]Limit, ⊔=lower-duration)` |
| `MetaData` merge in `Apply`        | `internal/policy/apply.go` (inline) | `(map[string]any, ⊔=overwrite)` |

The struct-monoid extension would let us prove e.g.
"every output entry's duration ≤ corresponding input entry's duration",
which is the load-bearing correctness statement for these merges.

### D. Authoring opportunities (no toolchain blocker)

These functions are within the existing translator's reach but no lemma
has been written:

1. `internal/policy/util.go:67-77` `greaterThanInt64` — pure 3-branch
   predicate, isomorphic to the int version we could trivially mirror.
   **Lemma idea:** `greaterThanInt64(-1, b) == true && greaterThanInt64(a, -1) == false` for `a != -1`.
2. `internal/policy/util.go:82-92` `greaterThanInt` — same shape, int.
3. `user/session.go` `RateLimit.Duration()` — non-negative-when-`Per>0`
   invariant. Currently blocked because the helper uses `time.Duration`
   arithmetic; could be modelled by a lemma over the `int` representative
   already used in `LemmaPolicy.Per`.
4. `user/session_tags.go:4-37` `TagsFromMetadata` — the tag-append branch
   maps directly to the `LemmaCountNonEmptyTags` invariant we already
   proved. A wrapper lemma proving `len(post.Tags) >= len(pre.Tags)`
   (slice-grows monotonicity) would make the production link explicit.
5. `internal/policy/apply.go:496-505` MaxQueryDepth merge — pure max
   over two integers; isomorphic to `MinLEMax` from the standard library.
6. `internal/policy/apply.go:533-538` QuotaMax monotone-take-max over
   two int64s — a `MaxGE_A` / `MaxGE_B` citation lemma.
7. `user/policy.go` `RateLimit.IsValid()` (if present) — non-negativity
   conjunction.

Each of these is a single-file addition; total estimated effort is
< 1h per lemma if the gosmt subset accepts the chosen integer
representative.

## Recommended next phases

In priority order:

1. **Phase S.2c.5 (monoid generalisation)** — unblocks the three big
   `Apply…Limits` proofs and is the highest production-impact gap.
2. **Phase S.2c.4 projection extension** — unblocks find-first lemmas,
   which are the second most common loop shape after the count-fold we
   already cover.
3. **Phase S.2c.3 nested loops** — unblocks `MergeAllowedURLs` and
   `applyACL`. Lower priority because the outer-by-inner product domain
   often admits a single-loop refactor.
4. **Authoring sweep on the D-list above** — straightforward, no
   toolchain work required; would push the corpus to ~57 PROVED.

## Methodology

* Coverage tool: `proof verify-lemma --coverage --solver z3
  --tags reqproof_proof <pkg>/...`
* Every entry in this document was verified by either:
  * a TRANSLATION_ERROR observed during this sweep (Phase S.2c.3 / .5);
  * the absence of any matching lemma directive in the source tree
    (`grep -rn 'reqproof:lemma' …`).
* No counterexamples were observed — i.e. every gap is an authoring or
  translator gap, not a production-correctness defect.
