# WAF A/B experiment contract

Status: Shared decisions and the WAF-GO plan were approved on 2026-08-21.
WAF-JS planning remains separate.

## Goal

Compare two credible inbound WAF implementations in Tyk Gateway:

- `waf-go`: native Coraza with OWASP CRS;
- `waf-js`: a CRS-derived JavaScript WAF in the existing Goja runtime.

The comparison determines whether independent JavaScript delivery is worth
its added implementation and runtime cost.

## Common baseline

- Gateway commit: `9a364e24c1d882429a40083d92ed8fc29f224f83`
- Gateway branch source: official `master`
- CRS release: OWASP CRS `v4.25.1` LTS, identical in both Tracks
- CRS target: Paranoia Level 1
- Inbound anomaly threshold: `5`, identical in both Tracks
- Request direction: inbound
- Corpus and benchmark environment: identical between Tracks

The CRS pin changes only through a contract amendment. Its approval evidence
and distribution decision are in `WAF-AB.contract-amendment.md`.

## Functional target

Cover attack families 930, 931, 932, 933, 934, 941, 942, 943, and 944.
Include compatible 920-series rules when Gateway exposes the required inputs.

Inspect query parameters, cookies, URL-encoded bodies, and JSON bodies.
Measure multipart and XML support. They do not block the first comparison.

Each result records allow or block, HTTP status, anomaly score when available,
matched rule IDs, and unsupported features.

Audit mode and fail-open are the defaults. Blocking is enabled explicitly per
API. A CRS block returns HTTP 403. A fail-closed internal failure returns HTTP
503. Neither response exposes transaction IDs, rule IDs, anomaly scores, or
engine errors.

## Shared test seam

The shared seam is the Gateway HTTP request boundary. `gateway.StartTest`
starts a full test Gateway. `ts.Run(t, test.TestCase...)` drives corpus cases
through the complete HTTP stack.

Both Tracks expose these entry points with identical semantics:

- `TestWAFSharedCorpus`
- `BenchmarkWAFShared`

Assertions use response status, response body, upstream reachability, and
recorded log or metric effects. A Track must not assert on the other Track's
internals.

## Shared corpus

The canonical corpus is a versioned JSON array under
`docs/dev/program/waf-corpus/`. Each case contains `schema_version`, `id`,
`attack_family`, `applicable`, `provenance`, `required_features`, `request`,
mode-keyed `expectations`, and optional `failure_policy`. Bodies use base64.
Unknown fields are rejected.

Every case receives exactly one classification:

- `pass`
- `unexpected_failure`
- `unsupported_feature`
- `host_unavailable`
- `not_applicable`

Applicable pass rate is reported separately from rules loaded.

`body_repeat` repeats the decoded body before it is assigned to
`test.TestCase.Data`. `failure_policy` supplies paired fail-open and
fail-closed expectations for one injected failure. Shared conformance tests
must prove that both runners generate identical request bytes and interpret
these fields identically.

Tests resolve the canonical fixture from the repository at runtime. They must
not embed, copy, fork, or relocate it into Track-specific test data.

## Shared benchmark

Both Tracks run this functional command unchanged:

```sh
go test -run=^TestWAFSharedCorpus$ -count=1 -tags 'goplugin dev' ./gateway/
```

Both Tracks run this benchmark command unchanged:

```sh
go test -run=NONE -bench=^BenchmarkWAFShared$ -benchmem -count=6 -benchtime=2s -tags 'goplugin dev' ./gateway/
```

Create one neutral measurement commit from the Common baseline. It adds only
the shared corpus and benchmark harness. Record its SHA and patch ID. Use it
for the canonical no-WAF samples and include the same harness in both Tracks.

Report concurrency levels 1, 8, and 64 for every configuration and matrix
case. Discard the first of six runs as warm-up. Report cold engine builds
separately from warm steady-state requests.

Initial A/B runs may use the same recorded, idle machine, including a developer
workstation. Record its OS, CPU, physical cores, memory, and whether it is bare
metal or a VM. Run no competing workload. If the ranking falls within observed
run-to-run noise, or supports an external claim, repeat it on one dedicated
host under the same conditions.

## Fairness rules

- Keep the Tracks independent after common setup.
- Share acceptance criteria, fixture bytes, benchmark commands, and results.
- Do not share Track implementation code.
- Each Track chooses the integration point that best fits its architecture.
- Do not force equal internal chain positions.
- Do not disable intervening middleware to make results appear equivalent.
- Record integration position and observable effects as measured differences.
- Record MCP/JSON-RPC support or `unsupported_feature`; never omit it silently.
- Distinguish rules loaded from applicable tests passed.
- Report generated code separately from maintained code.
- Measure a Gateway baseline without a WAF.
- Run one CRS upgrade exercise after the initial comparison works.

## Shared WAF log contract

The WAF outcome record uses this closed shared field list:

- `component`, `api_id`, `path`, `origin`
- `tx_id`, `mode`, `verdict`, `enforced`, `http_status`
- `anomaly_score` when available
- `matched_rule_ids`, `matched_rule_ids_count`, `matched_rule_ids_truncated`
- `inspection_scope`, `body_inspected`, `skip_reason`
- `failure_reason` on failure paths
- `inspection_duration_ms`

`trace_id` and `span_id` are optional correlation fields. Authentication-key
values are outside the shared WAF contract. The existing request logger may
add its obfuscated `key`, but corpus assertions must not require it. Neither
Track may emit a raw authentication key.

Audit and block modes use the same WAF fields. For the same request, only
`enforced`, `http_status`, and the level/message pair differ. Sort matched rule
IDs ascending and retain at most the first 20 while preserving the true count.
Rule IDs, transaction IDs, and anomaly scores never enter client responses.

## WAF-GO approved choices

- Insert WAF-GO after the non-MCP request-size limit and before
  `MiddlewareContextVars`.
- Exclude MCP/JSON-RPC APIs from the first comparison and report them as an
  unsupported feature.
- Rebuild an engine on reload. Add a configuration-hash cache only if measured
  build time or memory justifies it and the cache safety conditions hold.
- Use a 10 MiB body-inspection limit for the experiment. This is not an
  approved production default. Measurements may trigger a contract amendment.
- Use the Gateway's existing OTLP metrics route. Record exporter and endpoint
  settings with the evidence pack.
- Permit read-only access to public primary sources for dependency and upgrade
  verification. No provider credentials are authorised by this decision.

## Decision weights

| Category | Weight |
| --- | ---: |
| CRS compatibility and security fidelity | 25% |
| Request performance | 20% |
| Maintainability | 15% |
| Upgrade and release independence | 15% |
| Implementation complexity | 10% |
| Operational complexity | 5% |
| Security review surface | 5% |
| Extensibility | 5% |

Changing these weights after results exist requires a recorded reason.

## Required evidence

Both Tracks provide functional results, CRS compatibility, performance,
dependency and binary impact, maintained code size, failure behaviour,
observability, upgrade effort, maintainability, and productionisation effort.

The final recommendation uses measured evidence. Fewer lines alone cannot
select a Track.

## Workflow

Use LoopTroop for planning and execution. Sol and Opus are required independent
reviewers. Qwen implements the first ticket. GLM is the first rotating reviewer.
Use no automatic structured-output retry.

The owner approved this contract package and the WAF-GO choices on 2026-08-21.
The approval was: "Approved as recommended." One later owner decision selects
whether either Track should be productionised.

## Source

The complete 1,024-line brief is retained at
`docs/dev/program/WAF-AB.original-brief.md`. Load it only for planning or when a
contract detail is disputed.
