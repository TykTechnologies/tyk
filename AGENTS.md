# WAF A/B experiment

This repository is one track in a controlled WAF comparison.

Read in this order:

1. `docs/dev/program/WAF-AB.contract.md`
2. `docs/dev/program/WAF-TRACK.md`
3. Relevant Gateway code and documentation
4. `docs/dev/program/WAF-AB.original-brief.md` only when the contract points to it

Rules:

- Keep both tracks on the same Gateway and CRS baselines.
- Do not copy implementation code or track-specific assumptions between tracks.
- Reuse maintained libraries before writing common infrastructure.
- Record dependency provenance before adding a dependency.
- Design deep Modules with small Interfaces.
- Use vertical TDD at the agreed request-inspection Seam.
- Run the same functional corpus and benchmarks in both tracks.
- Separate maintained, generated, test, and configuration code in reports.
- Record unsupported CRS features. Do not silently omit them.
- Use short, precise technical English.
- Do not push, merge, or change the other track.

The workflow is plan, approve, implement, verify, independently review, compare,
and make one final productionisation decision.
