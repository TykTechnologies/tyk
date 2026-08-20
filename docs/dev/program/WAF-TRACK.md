# WAF Track: JavaScript

Status: Ready for planning

## Objective

Build a useful CRS-derived WAF in the existing Goja runtime. Keep the WAF and
generated rules distributable without rebuilding Gateway.

## Constraints

- Keep CRS semantics in JavaScript or build-time tooling, not Go.
- Add only generic Goja security capabilities that the WAF demonstrably needs.
- Expose a curated request snapshot, never `*http.Request`.
- Preserve request bodies in an exact binary-safe representation.
- Bound regex patterns, caches, request state, body size, and execution time.
- Report every unsupported CRS feature. Do not silently omit rules.
- Record fail-open or fail-closed behavior for every internal error.
- Measure maintained Go, JavaScript, tooling, and generated code separately.

## Before implementation

The plan must:

1. research and pin CRS plus the parser or CRSLang tooling;
2. map the current Goja request, body, and lifecycle capabilities;
3. name the public request-inspection test Seam;
4. define the minimum generic ABI delta;
5. define the shared corpus and benchmark commands; and
6. report the target rules that depend on unsupported libinjection behavior.

Do not change or copy the native Go Track.
