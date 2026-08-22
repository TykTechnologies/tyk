// Package wafjs hosts the waf-js track's CRS-derived WAF engine.
//
// The package is a deep module with a three-method interface. Build loads
// and validates the pinned engine and ruleset artifacts, compiles them once
// per API load, and swaps the active engine atomically; a failed Build
// leaves the previously built engine active. Inspect runs one inspection on
// a fresh transaction over a curated request snapshot and returns the
// documented Finding or a typed *Failure. Close deactivates the engine.
//
// The engine runtime is WAF-owned and separate from spec.GojaJSVM and the
// custom JavaScript middleware. It exposes the ECMAScript built-ins of the
// pinned goja plus two ABI globals: the bound ruleset
// (globalThis.wafjsRuleset) and the engine's single inspection entry point
// (globalThis.wafjsInspect). No network, filesystem, process, timer,
// storage, or Tyk plugin API reaches the runtime, and every inspection uses
// a fresh runtime, so no runtime or transaction is shared between requests.
//
// Artifact validation covers schema, version, the CRS pin (crs_release,
// crs_manifest_sha256), digest, size, and path bounds against the
// configured root. CRS semantics stay in engine JavaScript and build-time
// tooling; this package never parses CRS content.
//
// The interrupt capability spike evidence for the pinned engine lives in
// spike_interrupt_test.go and
// docs/dev/program/waf-js/goja-capability-map.md.
package wafjs
