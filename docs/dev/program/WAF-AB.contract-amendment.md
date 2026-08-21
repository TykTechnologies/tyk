# WAF A/B — Contract Decision Record

Status: accepted with amendments and applied on 2026-08-21. Scope: both
Tracks. Source stories: US-4, US-5, US-2, US-12, US-13, US-15, US-16 of the
WAFG-3 PRD. This file is the decision history; `WAF-AB.contract.md` is
authoritative.

## 1. Rules governing this amendment

1. **Decision record.** This document records the proposed text, owner
   amendments, and application to `docs/dev/program/WAF-AB.contract.md`.
2. **Per-item acceptance.** Each item carries its own acceptance marker below.
   The owner may accept, amend, or reject items individually; one item's
   rejection does not block another's acceptance.
3. **Verbatim adoption.** Once an item is accepted, waf-js must adopt the
   accepted form verbatim, and neither Track may vary it without a further
   contract amendment. A per-track deviation is never silently absorbed.
4. **Slice-start dependency.** No implementation slice starts before the
   amendment items it depends on are accepted and applied. The source WAF-GO
   planning record is retained in commit `b6d39bd72`; this branch keeps only
   the shared decisions needed by WAF-JS.
5. **Quotation rule.** Each item quotes the exact contract clause it amends or
   extends, or states "not currently specified" when the contract is silent.
6. **Normative source.** Once accepted and applied, the amended
   `WAF-AB.contract.md` is the sole normative copy of shared decisions. The
   plan, corpus, and benchmark documents explain and implement that contract;
   they do not create a second binding definition.

## 2. Summary of items

| Item | Shared decision | Source story | Blocks slices |
| --- | --- | --- | --- |
| 1 | Test Seam and shared entry point names | US-5 | Slice 2 (all corpus slices) |
| 2 | Per-Track integration-point rule including MCP reporting | US-4 | Slice 2 |
| 3 | Corpus fixture format, canonical corpus location, result classification enum | US-15 | Slice 2 (all corpus slices) |
| 4 | Benchmark entry point, exact command line, concurrency levels, count/benchtime, measurement host | US-16 | Slice 8 |
| 5 | Pinned CRS release with paranoia level and anomaly threshold | US-2 | Slice 1 (pin gate, then all) |
| 6 | Fail-closed status split: 503 versus 403 | US-12 | Slice 2, Slice 6 |
| 7 | Shared log field names for audit-mode assertions | US-13 | Slice 2 |

## 3. Item 1 — Test Seam and shared entry point names

**Current text.** The contract gates but does not define the Seam. Common
Baseline, closing paragraph:

> "Do not start implementation until the CRS pin, corpus format, benchmark
> command, and request-inspection Seam are approved."

The Seam itself and the entry-point names are **not currently specified**.

**Accepted text** (additional clause, Common Baseline):

> The shared request-inspection Seam is the Gateway HTTP request boundary
> driven by the existing e2e framework: `gateway.StartTest` starts a full test
> gateway, a WAF-enabled API spec is loaded, and `ts.Run(t, test.TestCase...)`
> drives each corpus case through the complete HTTP stack. Both Tracks expose
> the shared entry points `TestWAFSharedCorpus` (functional corpus) and
> `BenchmarkWAFShared` (benchmark) with identical semantics and consume the
> identical accepted fixture bytes. All corpus assertions are made at this
> Seam using response status, body match, whether the test upstream was
> reached, and recorded log and metric side effects only; audit-mode verdicts
> are asserted primarily by upstream reachability plus response status and
> secondarily by the structured log record (Item 7). Neither Track asserts on
> the other Track's internals.

**Source story.** US-5 (Test seam), recorded in WAF-GO commit `b6d39bd72` and
`docs/dev/program/WAF-AB.corpus.md` Section 10.

**Why it must be shared.** The comparison is valid only if both Tracks are
driven through the same boundary with the same assertion channels; the Seam is
one of the four approval gates the contract already names.

**Blocks.** Slice 2 (the first request-inspection slice) and every later
corpus-driven slice.

**Acceptance:** [x] accepted and applied — 2026-08-21.

## 4. Item 2 — Per-Track integration point including MCP reporting

**Current text.** **Not currently specified.** The nearest clauses are
Fairness rules: "Keep the Tracks independent after this common setup." and
"Share acceptance criteria, corpus, benchmark commands, and measurement
format." — neither names a chain position.

**Accepted text** (additional clause, Fairness rules):

> Each Track chooses and documents the integration point that best fits its
> implementation. The comparison does not require identical middleware-chain
> positions or other internal architecture. It requires the same Gateway
> baseline, API configuration, corpus bytes, external HTTP test Seam,
> benchmark method, and result format. Do not disable intervening Gateway
> middleware or exclude results merely to make the Tracks appear internally
> identical. Treat integration position and its observable effects as measured
> implementation differences. Each Track records MCP/JSON-RPC support or an
> Unsupported Feature; neither Track silently omits it.

**Source story.** US-4 (Chain position), recorded in WAF-GO commit
`b6d39bd72`.

**Why it must be shared.** The experiment compares complete solutions, not
isolated middleware calls. A shared external Seam and measurement contract
make results comparable while preserving each Track's natural architecture.

**Blocks.** Slice 2.

**Acceptance:** [x] accepted and applied — 2026-08-21.

## 5. Item 3 — Corpus fixture format, canonical corpus location, and result classification enum

**Current text.** Common Baseline:

> "- Corpus and benchmark environment: identical between Tracks"

Functional target:

> "Each result records allow or block, HTTP status, anomaly score when
> available, matched rule IDs, and unsupported features."

The fixture format, the canonical corpus location, and the classification
enum are **not currently specified**.

**Accepted text, amended by the owner** (additional clause, Common Baseline):

> The shared corpus format is defined in `docs/dev/program/WAF-AB.corpus.md`:
> a versioned JSON array of case objects (`schema_version`, `id`,
> `attack_family`, `applicable`, `provenance`, `required_features`,
> `request`, mode-keyed `expectations`, optional `failure_policy`), with
> bodies carried base64 and the request portion mapped onto the e2e
> framework's `test.TestCase` fields. Unknown case fields are rejected; the
> accepted fixture bytes are identical for both Tracks. Every executed case
> gets exactly one classification from the closed enum: `pass`,
> `unexpected_failure`, `unsupported_feature`, `host_unavailable`,
> `not_applicable`; applicable pass rate is reported separately from rules
> loaded.
>
> `body_repeat` is a shared runner instruction that repeats the decoded body
> before assigning `test.TestCase.Data`; both Tracks must produce identical
> bytes. A `failure_policy` object supplies paired `fail_open` and
> `fail_closed` expectations for the same injected internal failure. Both are
> required shared runner behaviour, not Track-specific extensions. Shared
> conformance tests prove that both runners generate identical bytes and
> interpret these fields identically.
>
> The canonical corpus location is `docs/dev/program/waf-corpus/` (example
> fixture: `docs/dev/program/waf-corpus/example-corpus.json`). Tests resolve
> it from the repository at runtime. They do not embed, copy, fork, or
> relocate it into Track-specific test data.

**Canonical corpus location decision — recorded explicitly.** The corpus
**stays** under `docs/dev/program/waf-corpus/`; it does **not** move into a
test data directory. Grounds: the corpus is an experiment artefact shared by
both Tracks and consumed at the shared Seam, not a package-private Go test
fixture; and no `gateway/testdata` directory exists today (observed at the
pinned baseline), so a move would create a new layout convention rather than
follow one. The location moves only by amendment to
`docs/dev/program/WAF-AB.contract.md`
(`docs/dev/program/WAF-AB.corpus.md` Section 1); no Track may copy, fork, or
relocate the fixture.

**Source story.** US-15 (Corpus format), specified in
`docs/dev/program/WAF-AB.corpus.md` in full.

**Why it must be shared.** Both Tracks must replay byte-identical cases and
classify results identically, or the functional comparison and the CRS
compatibility weight (25%) are meaningless; corpus format is one of the four
approval gates the contract already names.

**Blocks.** Slice 2 (the failing corpus test is written first) and every
corpus-driven slice.

**Acceptance:** [x] amended and applied — 2026-08-21. Added runner
conformance tests and runtime use of the canonical fixture without copies.

## 6. Item 4 — Benchmark entry point, command line, concurrency levels, count/benchtime, and dedicated host

**Current text.** Common Baseline:

> "- Corpus and benchmark environment: identical between Tracks"

Fairness rules:

> "- Use warm and cold measurements on the same host."

The benchmark entry point, exact command line, concurrency levels, count and
benchtime values, and dedicated host specification are **not currently
specified**.

**Accepted text, amended by the owner** (additional clause, Common Baseline):

> The shared benchmark entry point is `BenchmarkWAFShared`. Both Tracks run
> this exact command line, verbatim, as a single command with no variation:
>
> ```
> go test -run=NONE -bench=^BenchmarkWAFShared$ -benchmem -count=6 -benchtime=2s -tags 'goplugin dev' ./gateway/
> ```
>
> Before either WAF implementation is applied, create one neutral measurement
> commit from the Common Baseline that adds only the shared corpus and
> benchmark harness. Record its SHA and patch ID. Run the command there once
> for the canonical `no-waf` samples, then include that byte-identical harness
> in both Track branches for their `audit` and `block` samples. A Track-local
> disabled-WAF run is diagnostic only and cannot replace the canonical
> baseline. `BenchmarkWAFShared` exposes configuration, request case, and
> concurrency (`1`, `8`, `64`) as named sub-benchmark axes.
>
> Both Tracks report functional corpus results from the same entry point:
>
> ```
> go test -run=^TestWAFSharedCorpus$ -count=1 -tags 'goplugin dev' ./gateway/
> ```
>
> Concurrency levels are 1, 8, and 64 in-flight requests, reported for every
> configuration and matrix case. `-count=6` with the first run discarded as
> warm-up; `-benchtime=2s`. Initial A/B runs may use the same recorded, idle
> machine, including a developer workstation. Record its OS, CPU model,
> physical cores, memory, and whether it is bare metal or a VM. Run no
> competing workload. Cold engine-build runs are reported separately from
> warm steady-state runs. If the ranking falls within observed run-to-run
> noise, or supports an external claim, repeat it on one dedicated host under
> the same conditions.

**Source story.** US-16 (Benchmark interface), specified in
`docs/dev/program/WAF-AB.benchmarks.md` Sections 1–5, 8, 12.

**Why it must be shared.** Identical benchmark commands and measurement
preconditions are contract Fairness rules; without pinned parameter values
each Track could measure on its own terms, and the request-performance weight
(20%) could not be defended. The benchmark command is one of the four
approval gates the contract already names.

**Blocks.** Slice 8 (benchmarks and evidence pack); no measurement before it.

**Acceptance:** [x] amended and applied — 2026-08-21. A controlled developer
workstation is permitted initially; close or externally reported results need
a dedicated-host rerun.

## 7. Item 5 — Pinned CRS release with paranoia level and anomaly threshold

**Current text.** Common Baseline:

> "- CRS release: must be researched and pinned before implementation"

> "- CRS target: Paranoia Level 1"

> "- Blocking behavior: equivalent anomaly threshold"

The pinned release and its evidence were recorded during WAF-GO planning but
were **not then specified** in the contract; the numeric inbound anomaly
threshold was not named —
"equivalent anomaly threshold" names no value.

**Accepted text** (replacement of the "CRS release" and "Blocking behavior"
clauses):

> "- CRS release: OWASP CRS v4.25.1 (LTS), pinned; the same pin binds both
> Tracks and changes only by contract amendment"

> "- Blocking behavior: identical inbound anomaly threshold 5
> (`tx.inbound_anomaly_score_threshold=5`, the pinned CRS v4.25.1 default
> quoted from the release's `crs-setup.conf.example`), at Paranoia Level 1,
> identical in both Tracks; either value changes only by contract amendment"

**Source story.** US-2 (CRS pin), evidenced in WAF-GO commit `b6d39bd72` from
the OWASP CRS release and its `crs-setup.conf.example`.

**Why it must be shared.** The CRS pin must bind both Tracks identically;
the threshold value must be named because blocking equivalence at different
numbers would produce different verdicts on the same corpus and void the
comparison.

**Blocks.** Slice 1 (both pins accepted) — and, through the contract's own
gate, every implementation slice.

**Acceptance:** [x] accepted and applied — 2026-08-21.

## 8. Item 6 — Fail-closed status split: 503 versus 403

**Current text.** **Not currently specified.** The nearest clause is the
Functional target's result-recording rule:

> "Each result records allow or block, HTTP status, anomaly score when
> available, matched rule IDs, and unsupported features."

It records statuses per result but fixes none for a WAF block or an internal
failure.

**Accepted text** (additional clause, Functional target):

> A CRS block returns HTTP 403: the engine worked and made a policy decision.
> A fail-closed internal failure returns HTTP 503: the engine could not
> inspect, so service is unavailable for that request. No third status is
> introduced. Both Tracks return 403 for WAF blocks and 503 for fail-closed
> internal failures identically, rendered through each Track's equivalent of
> the same error-handling surface; audit mode produces neither status. No
> transaction ID, rule IDs, anomaly score, or engine error text appears in
> either response body or headers.

**Source story.** US-12 (Block and failure responses), recorded in WAF-GO
commit `b6d39bd72` and approved as binding both Tracks.

**Why it must be shared.** Failure behaviour is required contract evidence,
and evidence must be able to distinguish a policy decision from a broken
engine in both Tracks; if the Tracks split statuses differently, corpus
status assertions and failure-behaviour evidence stop lining up.

**Blocks.** Slice 2 (the 403 block response) and Slice 6 (the fail-closed 503
path).

**Acceptance:** [x] accepted and applied — 2026-08-21.

## 9. Item 7 — Shared log field names for audit-mode assertions

**Current text.** **Not currently specified.** The nearest clause is the
Fairness rule:

> "Share acceptance criteria, corpus, benchmark commands, and measurement
> format."

No clause names log fields.

**Accepted text, amended by the owner** (additional clause, Fairness rules):

> The structured WAF log record carries exactly this closed field list:
> `component`, `api_id`, required request correlation (`path`, `origin`),
> optional `trace_id`/`span_id`,
> `tx_id`, `mode`, `verdict`, `enforced`, `http_status`, `anomaly_score`
> (when available), `matched_rule_ids`, `matched_rule_ids_count`,
> `matched_rule_ids_truncated`, `inspection_scope`, `body_inspected`,
> `skip_reason`, `failure_reason` (failure paths only), and
> `inspection_duration_ms`. Audit and block modes emit the same fields; for
> the same request only `enforced`, `http_status`, and the level/message pair
> differ. `matched_rule_ids` is capped at the first 20 IDs after an ascending
> sort, with the true count preserved. waf-js emits records with the same
> field names and the same values for these fields; matched rule IDs,
> transaction IDs, and anomaly scores appear in logs only, never in client
> responses. Authentication-key values are outside the shared WAF contract.
> The existing request logger may add its obfuscated `key`, but corpus
> assertions do not require it. Neither Track may emit a raw authentication
> key.

**Source story.** US-13 (Log records), recorded in WAF-GO commit `b6d39bd72`.

**Why it must be shared.** Audit-mode corpus verdicts are asserted secondarily
by matching this structured record (behind upstream reachability plus status),
so the field names are part of the shared contract surface: a single Track's
field change must fail that Track's corpus assertion loudly rather than
silently invalidating the comparison.

**Blocks.** Slice 2 (audit-mode secondary assertions land with telemetry).

**Acceptance:** [x] amended and applied — 2026-08-21. The obfuscated key is
not a required WAF field; trace and span identifiers are optional.

## 10. Application record

All seven items were applied to `docs/dev/program/WAF-AB.contract.md` on
2026-08-21. Items 3, 4, and 7 include the owner's amendments recorded above.
The owner also approved the WAF-GO choices for chain position, first-slice MCP
exclusion, reload, the experiment-only 10 MiB body limit, OTLP metrics,
read-only public primary-source access, audit mode, and fail-open defaults.
The authoritative contract now carries those decisions.
