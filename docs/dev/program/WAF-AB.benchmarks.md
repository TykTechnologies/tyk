# WAF A/B — Shared Benchmark Interface and Measurement Preconditions

Status: accepted with amendments on 2026-08-21. Scope: both Tracks. The
authoritative requirements are in `WAF-AB.contract.md`.

## 1. Configurations

Every benchmark run executes in exactly one of three configurations:

| Configuration | Meaning |
| --- | --- |
| `no-waf` | A neutral measurement commit derived from the common baseline. It adds only the shared corpus and benchmark harness, with no WAF implementation. Measures Gateway overhead alone. |
| `audit` | Track WAF loaded with the pinned CRS, detection only. Requests are never blocked. |
| `block` | Track WAF loaded with the pinned CRS, blocking enforcement at the common anomaly threshold. |

The neutral measurement commit is created first and its exact SHA and patch
ID are recorded. The command runs there once to produce the canonical
`no-waf` samples. The byte-identical harness commit is then included in both
Track branches, where the same command produces that Track's `audit` and
`block` samples. Both result tables reuse the one canonical `no-waf` sample
set; a Track-local disabled-WAF run is only a diagnostic and cannot replace it.

## 2. Request matrix

Each configuration is measured across the following request matrix:

| Matrix case | Shape |
| --- | --- |
| `small-query` | One short query parameter. |
| `many-query-params` | Many query parameters (proposed: 50). |
| `small-json-body` | Small JSON body (proposed: under 1 KiB). |
| `medium-json-body` | Medium JSON body (proposed: about 64 KiB). |
| `body-at-limit` | Body exactly at the maximum inspected size. |
| `body-over-limit` | Body over the inspection bound; exercises the configured limit path. |
| `one-rule-match` | Request matching exactly one CRS rule. |
| `many-rule-matches` | Request matching many CRS rules (proposed: 10 or more). |

## 3. Benchmark command

Both Tracks run this exact command line, verbatim, as a single command with
no variation:

```
go test -run=NONE -bench=^BenchmarkWAFShared$ -benchmem -count=6 -benchtime=2s -tags 'goplugin dev' ./gateway/
```

The command follows observed repository conventions: `-run=NONE` matches
`BENCH_RUN=NONE` (Makefile:19) used by the `bench` target (Makefile:30-32)
whose `BENCH_REGEX` default is `.` (Makefile:18), narrowed here to the single
shared benchmark; `-tags 'goplugin dev'` matches the default test tags at
`.taskfiles/test.yml:18`.

`BenchmarkWAFShared` is the single shared benchmark entry point. On the
neutral commit it runs `no-waf` and marks the unavailable WAF configurations
as skipped. On each Track it runs `audit` and `block`. It represents
configuration, matrix case, and concurrency (`1`, `8`, `64`) as three named
`b.Run` axes, so the fixed command needs no hidden flags or per-Track
variation. It follows the `b.Run` structure of
`gateway/mw_oas_validate_request_benchmark_test.go` and
`gateway/mw_certificate_check_benchmark_test.go`. No benchmark Go code is
added by this ticket; the named entry point is a specification for later
implementation beads.

## 4. Shared functional command

Both Tracks report functional corpus results from the same entry point:

```
go test -run=^TestWAFSharedCorpus$ -count=1 -tags 'goplugin dev' ./gateway/
```

`TestWAFSharedCorpus` is the shared request-inspection Seam defined in
`docs/dev/program/WAF-AB.corpus.md` Section 10. `-count=1` matches the
repository test default (`TEST_COUNT=1`, Makefile:16). Functional result
classification and reporting follow the corpus document.

## 5. Measurement preconditions

- Measurement host: initial A/B runs may use the same recorded, idle machine,
  including a developer workstation. Record its OS, CPU model, physical cores,
  memory, and whether it is bare metal or a VM.
- No other workload runs on the machine during a run. If the ranking is within
  observed noise, or supports an external claim, repeat both Tracks on one
  dedicated host.
- Proposed concurrency levels: 1, 8, and 64 in-flight requests, reported for
  every configuration and matrix case.
- Repetition: `-count=6`; the first run is discarded as warm-up and the
  remaining five runs are reported.
- Cold versus warm: measure engine construction at API load or reload as a
  separate cold metric. Measure the first inspected request separately if
  useful, but do not include engine construction in request latency. Warm
  steady-state numbers never average in cold-start samples.

## 6. Environment block

Every result table carries this environment block:

| Field | Content |
| --- | --- |
| Gateway commit | Exact commit measured: neutral harness, waf-go, or waf-js. |
| Benchmark harness | Neutral harness commit SHA and stable patch ID; both Track copies must match. |
| Go version | `go version` output. |
| OS | Host operating system and version. |
| CPU | CPU model. |
| Physical cores | Physical core count. |
| Memory | Total RAM. |
| Host type | Bare metal or VM. |
| CRS manifest hash | Hash of the pinned CRS manifest. |
| Engine version | Coraza release for `waf-go`; JavaScript engine version for `waf-js`. |
| Command line | The exact command line executed, verbatim. |

## 7. Reported metrics

Both Tracks fill the same two-column table:

| Metric | Coraza (`waf-go`) | JS (`waf-js`) |
| --- | --- | --- |
| ns/op | | |
| B/op | | |
| allocs/op | | |
| Throughput (req/s) | | |
| p50 / p95 / p99 latency | | |
| CPU per run | | |
| Steady-state memory | | |
| GC impact (pause count and total) | | |
| Engine build time (cold) | | |
| Compiled-rule memory | | |
| Binary size delta | | |
| Dependency count delta | | |

ns/op, B/op, and allocs/op come directly from the benchmark command output.
Latency, throughput, CPU, memory, and GC figures are collected per run at
each concurrency level. No performance pass threshold is invented before
comparison evidence exists; this document defines measurement format only.

## 8. Proposal status and comparability rule

Concurrency levels, `-count` and `-benchtime` values, the package path, and
the host specification are proposals until the owner accepts them as
amendment items. Host and parameter approval appears as one open-decision
entry. After acceptance, both Tracks use the accepted values without
variation. A run with differing values is non-comparable and requires a
re-run on the accepted parameters.

## 9. Binary size and dependency count

Binary size: build with the repository's standard build target
(`go build -tags "coprocess grpc goplugin" -trimpath .`, Makefile:46) at the
common baseline commit, then with each Track applied. Report the size delta
against the `no-waf` baseline binary in bytes, same host and Go version.

Dependency count: record the module count of `go list -m all` for the
baseline and for each Track; report the count delta and the list of added
modules. Provenance is recorded before any dependency is added, per the
repository rules.

## 10. Code-size counting

Maintained code size is counted per category, separating:

1. maintained Go;
2. maintained JavaScript;
3. generated code;
4. test code;
5. configuration;
6. external rule content (CRS).

Counting method: non-blank source lines per file, grouped by category, with
each category's file list recorded so the count is reproducible. Generated
and external content is reported separately and never summed into maintained
totals.

## 11. Result storage

All results live in one comparable table per metric family, both Tracks side
by side, carrying the Section 6 environment block. Raw samples — the unedited
benchmark command output for every run — are retained next to the tables so
any derived number traces to its sample. Proposed location:
`docs/dev/program/waf-results/`.

## 12. Approval gate

The owner approved the commands and amended measurement conditions on
2026-08-21. A later change requires a contract amendment before benchmark
implementation continues.
