# WAF Track: JavaScript

Status: Ready for planning

## Objective

Build a useful CRS-derived WAF in the existing Goja runtime. Keep the WAF and
generated rules distributable without rebuilding Gateway.

## Constraints

- Keep CRS semantics in JavaScript or build-time tooling, not Go.
- Add only generic Goja security capabilities that the WAF demonstrably needs.
- Gate the WAF with its own global and per-API settings. Do not make it depend
  on `enable_jsvm`, which continues to control custom JavaScript middleware
  and virtual endpoints.
- Expose a curated request snapshot, never `*http.Request`.
- Preserve request bodies in an exact binary-safe representation.
- Bound regex patterns, caches, request state, body size, and execution time.
- Report every unsupported CRS feature. Do not silently omit rules.
- Record fail-open or fail-closed behavior for every internal error.
- Use the Gateway's existing OTLP route. Record the Track's bounded metric
  names; do not claim that the shared contract defines metric names.
- Measure maintained Go, JavaScript, tooling, and generated code separately.

## Before implementation

The plan must:

1. verify the approved CRS pin and research parser or CRSLang tooling;
2. map the current Goja request, body, and lifecycle capabilities;
3. choose the integration point that best fits the JavaScript architecture;
4. define a runner at the approved public HTTP test Seam;
5. define the minimum generic ABI delta;
6. use the approved shared corpus and benchmark commands; and
7. report the target rules that depend on unsupported libinjection behavior.

Do not use the native Go plan as an architecture template. Compare the final
solutions only through the shared contract and measured evidence.
