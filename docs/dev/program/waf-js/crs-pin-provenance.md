# CRS pin and conversion-tool provenance

Track: waf-js. Gates the generator bead's SecLang parser choice.

## CRS pin

| Fact | Value |
| --- | --- |
| Release | OWASP CRS v4.25.1 LTS (contract common baseline) |
| Source repository | https://github.com/coreruleset/coreruleset |
| Tag | `v4.25.1` (annotated tag object `85d2ebd0beeea0b422a4c9cadba85a05dd7955eb`) |
| Resolved commit | `3b89d5a05322f448b4b74b9cadc5fb05ac6915ad` |
| Archive | https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.25.1.tar.gz |
| Archive SHA-256 | `0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154` (600,591 bytes) |
| Licence | Apache-2.0 (`LICENSE` in the tagged tree) |
| LTS release metadata | GitHub release `v4.25.1`, published 2026-07-02 |

Primary sources, retrieved 2026-08-21 (archive SHA-256 and licence re-verified
locally from the downloaded archive on 2026-08-22):

- Tag ref: https://api.github.com/repos/coreruleset/coreruleset/git/refs/tags/v4.25.1
- Annotated tag object: https://api.github.com/repos/coreruleset/coreruleset/git/tags/85d2ebd0beeea0b422a4c9cadba85a05dd7955eb
- Release metadata: https://github.com/coreruleset/coreruleset/releases/tag/v4.25.1
- Source archive: https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.25.1.tar.gz
- Licence file at tag: https://github.com/coreruleset/coreruleset/blob/v4.25.1/LICENSE

The pin matches the contract's common baseline (`WAF-AB.contract.md`, "Common
baseline"). Per that contract, the pin changes only through a contract
amendment.

## Conversion-tool candidates

The generator bead needs to read CRS SecLang directives and produce a
deterministic intermediate representation. Each candidate is assessed against
the reuse ladder: maintenance status, licence, public API stability,
deterministic output, runtime coupling.

### Chosen: purpose-built minimal SecLang-subset reader

A track-local reader covering only the directive forms the corpus requires
(directives used by attack families 930-934, 941-944, and compatible 920-series
rules; see the functional target in `WAF-AB.contract.md`), emitting a
deterministic intermediate representation with no engine runtime.

- Maintenance status: owned by this track; no external maintainer risk.
- Licence: same repository licence; no new licence exposure.
- Public API stability: internal to this track; the generator bead defines it.
- Deterministic output: pure function of input text; no engine state.
- Runtime coupling: none; parsing is decoupled from evaluation.
- Cost: bounded by the recorded SecLang subset; unsupported CRS features are
  recorded per the contract, not silently dropped.

Rejected candidates below make this choice auditable rather than a default.

### Rejected: coraza `v3.7.0` (github.com/corazawaf/coraza)

- Maintenance status: pass (actively maintained).
- Licence: pass (Apache-2.0, confirmed on pkg.go.dev for `coraza/v3`).
- Public API stability: fail — the SecLang parser lives in the internal
  `seclang` package; the only public ingestion path is `WithDirectives`.
- Deterministic output: fail — `WithDirectives` fuses parsing with WAF engine
  construction; the output is live engine state, not a convertible
  intermediate representation.
- Runtime coupling: fail — adopting it couples this track to the coraza engine
  and its evaluation semantics, pre-empting the comparison the contract
  requires.

Rejection reason: no public, deterministic parse output without dragging in the
engine.

### Rejected: go-ftw `v2.5.0` (github.com/coreruleset/go-ftw)

- Maintenance status: pass (maintained by the CRS project).
- Licence: pass (Apache-2.0).
- Artifact mismatch: go-ftw is the FTW YAML test harness for driving live WAFs
  over HTTP; it consumes tests, it does not parse or convert SecLang rules.

Rejection reason: wrong artifact — it cannot produce a rule intermediate
representation at any point on the ladder.

### Rejected: coraza-lsp (github.com/coraza-incubator/coraza-lsp)

- Maintenance status: fail (incubator project, experimental).
- Licence: pass (Apache-2.0).
- Public API stability: fail — parser lives under `internal/parser`; no stable
  public parse API.

Rejection reason: experimental status and internal-only parser; offers no
commitment the ladder requires.

### Rejected: seclang (github.com/ad3n/seclang)

- Maintenance status: fail (unmaintained).
- Licence: fail (no licence file; rights unclear, unusable for this track).

Rejection reason: no licence and no maintenance; fails the ladder's first two
rungs.

## Dependency impact

- Gateway module dependency list unchanged: `go list -m all` output is
  byte-identical to the recorded baseline (1,085 modules); `go.mod` and
  `go.sum` show no diff against Gateway commit
  `9a364e24c1d882429a40083d92ed8fc29f224f83`.
- No dependency was added during this research, per the AGENTS.md rule to
  record dependency provenance before adding a dependency.
- No Node or npm component is introduced by this record or the chosen
  conversion approach: no `package.json`, `node_modules`, lockfile, or npm
  invocation exists in this worktree, and the chosen reader adds none.
