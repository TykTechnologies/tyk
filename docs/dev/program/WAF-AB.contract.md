# WAF A/B experiment contract

Status: Setup complete; planning not started

## Goal

Compare two credible inbound WAF implementations in Tyk Gateway:

- `waf-go`: native Coraza with OWASP CRS;
- `waf-js`: a CRS-derived JavaScript WAF in the existing Goja runtime.

The comparison must determine whether independent JavaScript delivery is worth
its added implementation and runtime cost.

## Common Baseline

- Gateway commit: `9a364e24c1d882429a40083d92ed8fc29f224f83`
- Gateway branch source: official `master`
- CRS release: must be researched and pinned before implementation
- Request direction: inbound
- CRS target: Paranoia Level 1
- Blocking behavior: equivalent anomaly threshold
- Corpus and benchmark environment: identical between Tracks

Do not start implementation until the CRS pin, corpus format, benchmark command,
and request-inspection Seam are approved.

## Functional target

Cover attack families 930, 931, 932, 933, 934, 941, 942, 943, and 944.
Include compatible 920-series rules when Gateway exposes the required inputs.

Inspect query parameters, cookies, URL-encoded bodies, and JSON bodies.
Measure multipart and XML support. They do not block the first comparison.

Each result records allow or block, HTTP status, anomaly score when available,
matched rule IDs, and unsupported features.

## Fairness rules

- Keep the Tracks independent after this common setup.
- Share acceptance criteria, corpus, benchmark commands, and measurement format.
- Do not share Track implementation code.
- Distinguish rules loaded from applicable tests passed.
- Report generated code separately from maintained code.
- Measure a Gateway baseline without a WAF.
- Use warm and cold measurements on the same host.
- Run one CRS upgrade exercise after the initial comparison works.

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
dependency and binary impact, maintained code size, failure behavior,
observability, upgrade effort, maintainability, and productionisation effort.

The final recommendation uses measured evidence. Fewer lines alone cannot select
a Track.

## Workflow

Use LoopTroop for planning and execution. Sol and Opus are required independent
reviewers. Qwen implements the first ticket. GLM is the first rotating reviewer.
Use no automatic structured-output retry.

One owner decision approves each Track plan. One later owner decision selects
whether either Track should be productionised.

## Source

The complete 1,024-line brief is retained at
`docs/dev/program/WAF-AB.original-brief.md`. Load it only for planning or when a
contract detail is disputed.
